# frozen_string_literal: true

# name: mochirii-email-metadata
# about: Enforces recipient-visible mail metadata and a bounded Sidekiq processing probe.
# version: 1.1.1
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

    HEALTH_STATE_KEY = "mochirii-runtime-health-sidekiq-probe".freeze
    HEALTH_LEASE_GRACE_SECONDS = 30
    HEALTH_JOB_BIND_SECONDS = 5
    HEALTH_NONCE_PATTERN = /\A[0-9a-f]{32}\z/
    HEALTH_JID_PATTERN = /\A[0-9a-f]{24}\z/
    HEALTH_PREPARING_PATTERN = /\Apreparing:[0-9a-f]{32}\z/
    HEALTH_FAILURE_STATES =
      %w[
        cleanup-failed
        enqueue-rejected
        job-not-started-before-timeout
        job-reported-failure
        job-started-without-completion
        marker-mismatch
        probe-already-running
        probe-internal-failure
        run-mode-invalid
        transaction-open
      ].freeze

    HEALTH_TRANSITION_SCRIPT =
      DiscourseRedis::EvalHelper.new(<<~LUA)
        local current = redis.call("get", KEYS[1])
        if not current then
          return 0
        end
        if current ~= ARGV[1] then
          return -1
        end
        if redis.call("ttl", KEYS[1]) <= 0 then
          return -2
        end
        redis.call("set", KEYS[1], ARGV[2], "XX", "KEEPTTL")
        return 1
      LUA

    HEALTH_DELETE_SCRIPT =
      DiscourseRedis::EvalHelper.new(<<~LUA)
        local current = redis.call("get", KEYS[1])
        if not current then
          return 0
        end
        for index = 1, #ARGV do
          if current == ARGV[index] then
            redis.call("del", KEYS[1])
            return 1
          end
        end
        return -1
      LUA

    class SidekiqProbeError < StandardError
      attr_reader :state

      def initialize(state)
        raise ArgumentError, "Sidekiq probe state is outside the fixed allowlist" unless HEALTH_FAILURE_STATES.include?(state)

        @state = state
        super("Sidekiq processing probe failed (state=#{state})")
      end
    end

    class SidekiqProbeJobError < StandardError
      def initialize
        super("Mochirii Sidekiq processing probe job requires retry")
      end
    end

    def self.health_state_value(phase, identity)
      unless %w[preparing pending started failed completed].include?(phase)
        raise "Sidekiq processing probe phase is invalid"
      end
      pattern = phase == "preparing" ? HEALTH_NONCE_PATTERN : HEALTH_JID_PATTERN
      raise "Sidekiq processing probe identity is malformed" unless identity.is_a?(String) && identity.match?(pattern)

      phase + ":" + identity
    end

    def self.health_redis_key(redis)
      redis.namespace_key(HEALTH_STATE_KEY)
    end

    def self.health_probe_state
      Discourse.redis.get(HEALTH_STATE_KEY)
    end

    def self.health_monotonic_time
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    def self.health_sleep(seconds)
      sleep seconds
    end

    def self.transition_health_probe(expected, replacement)
      redis = Discourse.redis
      HEALTH_TRANSITION_SCRIPT
        .eval(
          redis.without_namespace,
          [health_redis_key(redis)],
          [expected, replacement],
        )
    end

    def self.claim_health_probe!(token, lease_seconds)
      preparing = health_state_value("preparing", token)
      acquired = Discourse.redis.set(HEALTH_STATE_KEY, preparing, nx: true, ex: lease_seconds)
      return preparing if acquired

      state = health_probe_state
      raise SidekiqProbeError.new(state.nil? ? "probe-internal-failure" : "probe-already-running"), cause: nil
    end

    def self.clear_health_probe!(token, jid)
      expected = [health_state_value("preparing", token)]
      if jid.is_a?(String) && jid.match?(HEALTH_JID_PATTERN)
        expected.concat(%w[pending started failed completed].map { |phase| health_state_value(phase, jid) })
      end
      redis = Discourse.redis
      result = HEALTH_DELETE_SCRIPT.eval(redis.without_namespace, [health_redis_key(redis)], expected)
      raise SidekiqProbeError.new("cleanup-failed"), cause: nil unless [0, 1].include?(result)
    rescue SidekiqProbeError
      raise
    rescue StandardError
      raise SidekiqProbeError.new("cleanup-failed"), cause: nil
    end

    def self.expected_health_phase(state, jid)
      return :missing if state.nil?
      %w[pending started failed completed].each do |phase|
        return phase.to_sym if state == health_state_value(phase, jid)
      end
      raise SidekiqProbeError.new("marker-mismatch"), cause: nil
    end

    def self.classify_health_probe_timeout(jid)
      phase = expected_health_phase(health_probe_state, jid)
      return :completed if phase == :completed
      raise SidekiqProbeError.new("job-reported-failure"), cause: nil if phase == :failed
      raise SidekiqProbeError.new("marker-mismatch"), cause: nil if phase == :missing
      state = phase == :started ? "job-started-without-completion" : "job-not-started-before-timeout"
      raise SidekiqProbeError.new(state), cause: nil
    end

    def self.verify_sidekiq_processing!(timeout_seconds: 60)
      health_probe_owned = false
      jid = nil
      unless timeout_seconds.is_a?(Integer) && timeout_seconds.between?(5, 120)
        raise "Sidekiq processing probe timeout is outside the exact boundary"
      end
      raise SidekiqProbeError.new("run-mode-invalid"), cause: nil unless Jobs.run_later?
      raise SidekiqProbeError.new("transaction-open"), cause: nil if DB.transaction_open?

      token = SecureRandom.hex(16)
      raise "Sidekiq processing probe token is malformed" unless token.match?(HEALTH_NONCE_PATTERN)

      preparing = claim_health_probe!(token, timeout_seconds + HEALTH_LEASE_GRACE_SECONDS)
      health_probe_owned = true
      jid = Jobs.enqueue(:mochirii_sidekiq_processing_probe, queue: "default")
      raise SidekiqProbeError.new("enqueue-rejected"), cause: nil unless jid.is_a?(String) && jid.match?(HEALTH_JID_PATTERN)
      pending = health_state_value("pending", jid)
      raise SidekiqProbeError.new("marker-mismatch"), cause: nil unless transition_health_probe(preparing, pending) == 1

      deadline = health_monotonic_time + timeout_seconds
      loop do
        phase = expected_health_phase(health_probe_state, jid)
        return true if phase == :completed
        raise SidekiqProbeError.new("job-reported-failure"), cause: nil if phase == :failed
        raise SidekiqProbeError.new("marker-mismatch"), cause: nil if phase == :missing
        if health_monotonic_time >= deadline
          return true if classify_health_probe_timeout(jid) == :completed
        end
        health_sleep(0.25)
      end
    rescue SidekiqProbeError
      raise
    rescue StandardError
      raise SidekiqProbeError.new("probe-internal-failure"), cause: nil
    ensure
      clear_health_probe!(token, jid) if health_probe_owned
    end
  end

  module ::Jobs
    class MochiriiSidekiqProcessingProbe < ::Jobs::Base
      def execute(_arguments = {})
        current_jid = jid
        return unless current_jid.is_a?(String) && current_jid.match?(MochiriiEmailMetadata::HEALTH_JID_PATTERN)

        pending = MochiriiEmailMetadata.health_state_value("pending", current_jid)
        started = MochiriiEmailMetadata.health_state_value("started", current_jid)
        completed = MochiriiEmailMetadata.health_state_value("completed", current_jid)
        bind_deadline =
          MochiriiEmailMetadata.health_monotonic_time + MochiriiEmailMetadata::HEALTH_JOB_BIND_SECONDS
        loop do
          state = MochiriiEmailMetadata.health_probe_state
          return if state.nil?
          if state.match?(MochiriiEmailMetadata::HEALTH_PREPARING_PATTERN)
            if MochiriiEmailMetadata.health_monotonic_time >= bind_deadline
              raise MochiriiEmailMetadata::SidekiqProbeJobError.new
            end
            MochiriiEmailMetadata.health_sleep(0.05)
            next
          end
          if state == started
            break
          end
          return unless state == pending
          transition = MochiriiEmailMetadata.transition_health_probe(pending, started)
          if transition != 1
            return unless MochiriiEmailMetadata.health_probe_state == pending
            raise MochiriiEmailMetadata::SidekiqProbeJobError.new
          end
          break
        end
        transition = MochiriiEmailMetadata.transition_health_probe(started, completed)
        if transition != 1 && MochiriiEmailMetadata.health_probe_state == started
          raise MochiriiEmailMetadata::SidekiqProbeJobError.new
        end
      rescue StandardError
        begin
          failed = MochiriiEmailMetadata.health_state_value("failed", current_jid)
          MochiriiEmailMetadata.transition_health_probe(started, failed)
        rescue StandardError
          # The caller reports only its fixed timeout state if the failure transition itself is unavailable.
        end
        raise MochiriiEmailMetadata::SidekiqProbeJobError.new, cause: nil
      end
    end
  end

  ActionMailer::Base.register_interceptor(::MochiriiEmailMetadata::Interceptor)
end
