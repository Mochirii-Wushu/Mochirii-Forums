# frozen_string_literal: true

# name: mochirii-email-metadata
# about: Enforces recipient-visible mail metadata and a bounded Sidekiq processing probe.
# version: 1.1.0
# authors: Mochirii
# url: https://github.com/Mochirii-Wushu/Mochirii-Forums

after_initialize do
  module ::MochiriiEmailMetadata
    require "securerandom"

    APPLICATION_HEADER_NAMES =
      %w[
        X-Discourse-Allow-Reply-By-Email
        X-Discourse-Email-Preview
        X-Discourse-Post-Id
        X-Discourse-Post-Ids
        X-Discourse-Topic-Id
        X-Discourse-Topic-Ids
        X-Discourse-Tags
        X-Discourse-Category
        X-Discourse-Sender
      ].map(&:downcase).freeze

    class Interceptor
      def self.delivering_email(message)
        message.header.fields.map { |field| field.name.to_s }.uniq.each do |name|
          next unless APPLICATION_HEADER_NAMES.include?(name.downcase)
          message[name] = nil
        end

        message
      end
    end

    HEALTH_NAMESPACE = "mochirii-runtime-health"
    HEALTH_PENDING_KEY = "sidekiq-pending"
    HEALTH_COMPLETION_KEY = "sidekiq-completion"
    HEALTH_MUTEX = "mochirii-runtime-health-sidekiq".freeze
    HEALTH_NONCE_PATTERN = /\A[0-9a-f]{32}\z/

    def self.with_health_mutex(&block)
      DistributedMutex.synchronize(HEALTH_MUTEX, &block)
    end

    def self.clear_health_probe!
      with_health_mutex do
        PluginStore.remove(HEALTH_NAMESPACE, HEALTH_PENDING_KEY)
        PluginStore.remove(HEALTH_NAMESPACE, HEALTH_COMPLETION_KEY)
      end
      unless PluginStore.get(HEALTH_NAMESPACE, HEALTH_PENDING_KEY).nil? &&
          PluginStore.get(HEALTH_NAMESPACE, HEALTH_COMPLETION_KEY).nil?
        raise "Sidekiq processing probe cleanup failed"
      end
    end

    def self.verify_sidekiq_processing!(timeout_seconds: 60)
      unless timeout_seconds.is_a?(Integer) && timeout_seconds.between?(5, 120)
        raise "Sidekiq processing probe timeout is outside the exact boundary"
      end
      token = SecureRandom.hex(16)
      raise "Sidekiq processing probe token is malformed" unless token.match?(HEALTH_NONCE_PATTERN)

      with_health_mutex do
        PluginStore.remove(HEALTH_NAMESPACE, HEALTH_PENDING_KEY)
        PluginStore.remove(HEALTH_NAMESPACE, HEALTH_COMPLETION_KEY)
        PluginStore.set(HEALTH_NAMESPACE, HEALTH_PENDING_KEY, token)
      end
      Jobs.enqueue(:mochirii_sidekiq_processing_probe, token: token)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout_seconds
      loop do
        completion = PluginStore.get(HEALTH_NAMESPACE, HEALTH_COMPLETION_KEY)
        return true if completion == token
        raise "Sidekiq processing probe observed a wrong completion token" unless completion.nil?
        raise "Sidekiq processing probe timed out" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        sleep 0.25
      end
    ensure
      clear_health_probe!
    end
  end

  module ::Jobs
    class MochiriiSidekiqProcessingProbe < ::Jobs::Base
      def execute(arguments)
        token = arguments[:token]
        unless token.is_a?(String) && token.match?(MochiriiEmailMetadata::HEALTH_NONCE_PATTERN)
          raise "Sidekiq processing job token is malformed"
        end

        MochiriiEmailMetadata.with_health_mutex do
          pending = PluginStore.get(
            MochiriiEmailMetadata::HEALTH_NAMESPACE,
            MochiriiEmailMetadata::HEALTH_PENDING_KEY,
          )
          if pending == token
            PluginStore.set(
              MochiriiEmailMetadata::HEALTH_NAMESPACE,
              MochiriiEmailMetadata::HEALTH_COMPLETION_KEY,
              token,
            )
          end
        end
      end
    end
  end

  ActionMailer::Base.register_interceptor(::MochiriiEmailMetadata::Interceptor)
end
