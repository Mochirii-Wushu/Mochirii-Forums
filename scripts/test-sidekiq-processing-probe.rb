# frozen_string_literal: true

# Deterministic source-only tests for the first-party Sidekiq processing probe.
# The exact plugin is loaded with minimal Discourse, Sidekiq, and Redis boundary
# stubs; no Rails application, Redis server, database, network, or standalone is
# used.

require "securerandom"
require "thread"

module ProbeHarness
  class FixtureError < StandardError
  end

  class WorkerWriteError < StandardError
  end

  class EnqueueError < StandardError
  end

  class ClaimWriteError < StandardError
  end

  RAW_WORKER_ERROR = "raw-worker-error-must-not-reach-caller"
  RAW_ENQUEUE_ERROR = "raw-enqueue-error-must-not-reach-caller"
  RAW_CLAIM_ERROR = "raw-claim-error-must-not-reach-caller"
  VALID_JID = "a" * 24
  SECOND_JID = "b" * 24
  INVALID_JID = "z" * 24
  WRONG_JID = "c" * 24
  FIXED_NONCE = "d" * 32

  class << self
    attr_accessor :bind_wait_entered,
                  :bind_wait_block,
                  :bind_wait_release,
                  :claim_write_then_raise,
                  :clock,
                  :completion_transition_failure,
                  :delete_override,
                  :enqueue_arguments,
                  :enqueue_count,
                  :enqueue_entered,
                  :enqueue_exception,
                  :enqueue_hold,
                  :enqueue_name,
                  :enqueue_release,
                  :event_fired,
                  :jid,
                  :mode,
                  :run_later,
                  :sleep_durations,
                  :spawn_worker_before_bind,
                  :takeover_after_delete,
                  :transaction_open,
                  :transition_nil_once,
                  :worker_exception,
                  :worker_thread
  end

  def self.redis
    @redis ||= FakeRedis.new
  end

  def self.reset(
    mode: :backlog,
    run_later: true,
    transaction_open: false,
    jid: VALID_JID,
    enqueue_exception: false,
    enqueue_hold: false,
    spawn_worker_before_bind: false,
    claim_write_then_raise: false,
    delete_override: nil,
    transition_nil_once: false,
    takeover_after_delete: false
  )
    worker_thread&.join
    redis.reset
    self.bind_wait_entered = Queue.new
    self.bind_wait_block = spawn_worker_before_bind
    self.bind_wait_release = Queue.new
    self.claim_write_then_raise = claim_write_then_raise
    self.clock = 0.0
    self.completion_transition_failure = mode == :job_exception
    self.delete_override = delete_override
    self.enqueue_arguments = nil
    self.enqueue_count = 0
    self.enqueue_entered = Queue.new
    self.enqueue_exception = enqueue_exception
    self.enqueue_hold = enqueue_hold
    self.enqueue_name = nil
    self.enqueue_release = Queue.new
    self.event_fired = false
    self.jid = jid
    self.mode = mode
    self.run_later = run_later
    self.sleep_durations = []
    self.spawn_worker_before_bind = spawn_worker_before_bind
    self.takeover_after_delete = takeover_after_delete
    self.transaction_open = transaction_open
    self.transition_nil_once = transition_nil_once
    self.worker_exception = nil
    self.worker_thread = nil
  end

  def self.enqueue(name, arguments = {})
    self.enqueue_count += 1
    self.enqueue_name = name
    self.enqueue_arguments = arguments.dup
    raise EnqueueError, RAW_ENQUEUE_ERROR if enqueue_exception
    if enqueue_hold
      self.enqueue_hold = false
      enqueue_entered << true
      enqueue_release.pop
    end
    if spawn_worker_before_bind
      self.spawn_worker_before_bind = false
      self.worker_thread = Thread.new { execute_job }
      bind_wait_entered.pop
    end

    jid
  end

  def self.execute_job(job_jid = jid)
    job = Jobs::MochiriiSidekiqProcessingProbe.new
    job.jid = job_jid
    begin
      job.execute({ "current_site_id" => "default" })
    rescue StandardError => error
      self.worker_exception = error
    end
  end

  def self.advance(seconds)
    self.clock += seconds
    sleep_durations << seconds
    return if event_fired

    case mode
    when :complete, :job_exception
      self.event_fired = true
      execute_job
    when :started_only
      self.event_fired = true
      redis.force_state("started:" + jid)
    when :wrong_state
      self.event_fired = true
      redis.force_state("completed:" + WRONG_JID)
    when :missing_state
      self.event_fired = true
      redis.force_absent
    end
  end

  def self.sleep(seconds)
    if seconds == 0.05 && bind_wait_block
      self.bind_wait_block = false
      bind_wait_entered << true
      bind_wait_release.pop
      return
    end
    advance(seconds)
    Thread.pass
  end
end

class FakeRedis
  attr_reader :delete_count, :expiry_history, :history, :lease_seconds

  def reset
    @delete_count = 0
    @expires_at = nil
    @expiry_history = []
    @history = []
    @lease_seconds = nil
    @store = {}
  end

  def namespace_key(key)
    "fixture:" + key
  end

  def without_namespace
    self
  end

  def canonical_key(key)
    key.start_with?("fixture:") ? key : namespace_key(key)
  end

  def get(key)
    canonical = canonical_key(key)
    expire_if_needed(canonical)
    @store[canonical]
  end

  def set(key, value, nx:, ex:)
    canonical = canonical_key(key)
    expire_if_needed(canonical)
    return nil if nx && @store.key?(canonical)

    @store[canonical] = value
    @history << value
    @lease_seconds = ex
    @expires_at = ProbeHarness.clock + ex
    @expiry_history << @expires_at
    if ProbeHarness.claim_write_then_raise
      ProbeHarness.claim_write_then_raise = false
      raise ProbeHarness::ClaimWriteError, ProbeHarness::RAW_CLAIM_ERROR
    end
    "OK"
  end

  def transition(key, arguments)
    expected, replacement = arguments
    canonical = canonical_key(key)
    expire_if_needed(canonical)
    current = @store[canonical]
    return 0 if current.nil?
    return -1 unless current == expected
    return -2 unless @expires_at.is_a?(Numeric) && @expires_at > ProbeHarness.clock
    if ProbeHarness.transition_nil_once
      ProbeHarness.transition_nil_once = false
      return nil
    end
    if replacement.start_with?("completed:") && ProbeHarness.completion_transition_failure
      ProbeHarness.completion_transition_failure = false
      raise ProbeHarness::WorkerWriteError, ProbeHarness::RAW_WORKER_ERROR
    end

    @store[canonical] = replacement
    @history << replacement
    @expiry_history << @expires_at
    if expected.start_with?("preparing:") && !ProbeHarness.bind_wait_release.nil?
      ProbeHarness.bind_wait_release << true
    end
    1
  end

  def delete_expected(key, expected)
    @delete_count += 1
    override = ProbeHarness.delete_override
    return nil if override == :nil
    return 0 if override == :zero
    return -1 if override == :minus_one
    raise ProbeHarness::WorkerWriteError, ProbeHarness::RAW_WORKER_ERROR if override == :raise

    canonical = canonical_key(key)
    expire_if_needed(canonical)
    current = @store[canonical]
    return 0 if current.nil?
    return -1 unless expected.include?(current)

    @store.delete(canonical)
    @history << nil
    @expires_at = nil
    if ProbeHarness.takeover_after_delete
      ProbeHarness.takeover_after_delete = false
      @store[canonical] = "pending:" + ProbeHarness::SECOND_JID
      @history << @store[canonical]
      @expires_at = ProbeHarness.clock + 90
      @expiry_history << @expires_at
    end
    1
  end

  def force_state(value, lease_seconds: 90)
    @store[namespace_key(MochiriiEmailMetadata::HEALTH_STATE_KEY)] = value
    @history << value
    @lease_seconds = lease_seconds
    @expires_at = ProbeHarness.clock + lease_seconds
    @expiry_history << @expires_at
  end

  def force_absent
    @store.delete(namespace_key(MochiriiEmailMetadata::HEALTH_STATE_KEY))
    @history << nil
    @lease_seconds = nil
    @expires_at = nil
  end

  private

  def expire_if_needed(canonical)
    return unless @store.key?(canonical) && @expires_at.is_a?(Numeric) && ProbeHarness.clock >= @expires_at

    @store.delete(canonical)
    @history << nil
    @expires_at = nil
  end
end

class DiscourseRedis
  class EvalHelper
    def initialize(script)
      @kind = script.include?("for index = 1") ? :delete : :transition
    end

    def eval(redis, keys, arguments)
      raise ProbeHarness::FixtureError, "probe Lua key count differed" unless keys.length == 1

      if @kind == :delete
        redis.delete_expected(keys.fetch(0), arguments)
      else
        redis.transition(keys.fetch(0), arguments)
      end
    end
  end
end

module Discourse
  def self.redis
    ProbeHarness.redis
  end
end

module Jobs
  class Base
    attr_accessor :jid
  end

  def self.run_later?
    ProbeHarness.run_later
  end

  def self.enqueue(name, arguments = {})
    ProbeHarness.enqueue(name, arguments)
  end
end

module DB
  def self.transaction_open?
    ProbeHarness.transaction_open
  end
end

module ActionMailer
  class Base
    class << self
      attr_reader :registered_interceptors

      def register_interceptor(interceptor)
        @registered_interceptors ||= []
        @registered_interceptors << interceptor
      end
    end
  end
end

def after_initialize(&block)
  block.call
end

load File.expand_path("../plugins/mochirii_email_metadata/plugin.rb", __dir__)

MochiriiEmailMetadata.define_singleton_method(:health_monotonic_time) do
  ProbeHarness.clock
end
MochiriiEmailMetadata.define_singleton_method(:health_sleep) do |seconds|
  ProbeHarness.sleep(seconds)
end

def assert_fixture(condition, message)
  raise ProbeHarness::FixtureError, message unless condition
end

def assert_health_state_absent
  assert_fixture(
    ProbeHarness.redis.get(MochiriiEmailMetadata::HEALTH_STATE_KEY).nil?,
    "health lease cleanup differed",
  )
end

def assert_cleanup_attempted
  assert_fixture(ProbeHarness.redis.delete_count >= 1, "owned probe did not attempt atomic cleanup")
end

def assert_state_only(error, expected_state)
  expected_message = "Sidekiq processing probe failed (state=#{expected_state})"
  assert_fixture(error.is_a?(MochiriiEmailMetadata::SidekiqProbeError), "probe error class differed")
  assert_fixture(error.state == expected_state, "probe error state differed")
  assert_fixture(error.message == expected_message, "probe error message was not state-only")
  assert_fixture(error.cause.nil?, "probe error retained a raw exception cause")
  assert_fixture(
    MochiriiEmailMetadata::HEALTH_FAILURE_STATES.include?(error.state),
    "probe error escaped its fixed state allowlist",
  )
  sensitive = [
    ProbeHarness.jid,
    ProbeHarness.enqueue_arguments&.inspect,
    ProbeHarness::RAW_WORKER_ERROR,
    ProbeHarness::RAW_ENQUEUE_ERROR,
    ProbeHarness::RAW_CLAIM_ERROR,
  ].compact.reject(&:empty?)
  assert_fixture(
    sensitive.none? { |value| error.message.include?(value) || error.full_message.include?(value) },
    "probe error disclosed a nonce, JID, arguments, or raw error",
  )
end

def expect_probe_state(expected_state)
  begin
    MochiriiEmailMetadata.verify_sidekiq_processing!
  rescue MochiriiEmailMetadata::SidekiqProbeError => error
    assert_state_only(error, expected_state)
    return error
  end
  raise ProbeHarness::FixtureError, "probe unexpectedly succeeded for #{expected_state}"
end

def assert_owned_cleanup
  assert_health_state_absent
  assert_cleanup_attempted
end

assert_fixture(
  ActionMailer::Base.registered_interceptors == [MochiriiEmailMetadata::Interceptor],
  "plugin interceptor registration differed",
)

# Success atomically claims one lease, enqueues only the explicit default queue,
# binds the returned JID, observes started/completed, retains the original TTL,
# and deletes only its own exact state.
ProbeHarness.reset(mode: :complete)
assert_fixture(MochiriiEmailMetadata.verify_sidekiq_processing!, "successful probe returned false")
ProbeHarness.worker_thread&.join
assert_fixture(ProbeHarness.enqueue_count == 1, "probe enqueue count differed")
assert_fixture(
  ProbeHarness.enqueue_name == :mochirii_sidekiq_processing_probe,
  "probe enqueued a different job",
)
assert_fixture(
  ProbeHarness.enqueue_arguments == { queue: "default" },
  "probe changed its default queue or added correlation arguments",
)
assert_fixture(
  ProbeHarness.redis.history.map { |value| value&.split(":", 2)&.first } ==
    %w[preparing pending started completed] + [nil],
  "probe state transition order differed",
)
assert_fixture(ProbeHarness.redis.lease_seconds == 90, "probe lease differs from the 60+30 boundary")
assert_fixture(
  ProbeHarness.redis.expiry_history.uniq == [90.0],
  "same-JID transitions changed the original lease expiry",
)
assert_owned_cleanup

# A worker that starts before enqueue returns waits for the caller's exact JID
# binding and then completes; it cannot turn a healthy fast worker into a false
# not-started result.
ProbeHarness.reset(mode: :backlog, spawn_worker_before_bind: true)
assert_fixture(MochiriiEmailMetadata.verify_sidekiq_processing!, "pre-bind worker did not complete")
ProbeHarness.worker_thread&.join
assert_fixture(ProbeHarness.worker_exception.nil?, "pre-bind worker unexpectedly requested retry")
assert_owned_cleanup

# Invalid run mode and an open transaction fail before claiming or enqueueing.
ProbeHarness.reset(run_later: false)
expect_probe_state("run-mode-invalid")
assert_fixture(ProbeHarness.enqueue_count.zero?, "invalid run mode reached enqueue")
assert_health_state_absent

ProbeHarness.reset(transaction_open: true)
expect_probe_state("transaction-open")
assert_fixture(ProbeHarness.enqueue_count.zero?, "open transaction reached enqueue")
assert_health_state_absent

# Enqueue acceptance is bound to a 24-hex JID. Raw enqueue failures are replaced
# by fixed caller state and the preparing lease is removed.
ProbeHarness.reset(jid: ProbeHarness::INVALID_JID)
expect_probe_state("enqueue-rejected")
assert_owned_cleanup

ProbeHarness.reset(enqueue_exception: true)
expect_probe_state("probe-internal-failure")
assert_owned_cleanup

ProbeHarness.reset(transition_nil_once: true)
expect_probe_state("marker-mismatch")
assert_owned_cleanup

# A write-then-raise ambiguity stays fail-closed under its TTL lease: no unowned
# caller deletes it, a competitor refuses it, and expiry permits recovery.
ProbeHarness.reset(claim_write_then_raise: true)
expect_probe_state("probe-internal-failure")
retained_claim = ProbeHarness.redis.get(MochiriiEmailMetadata::HEALTH_STATE_KEY)
assert_fixture(
  retained_claim&.match?(MochiriiEmailMetadata::HEALTH_PREPARING_PATTERN),
  "ambiguous claim did not retain its expiring preparing state",
)
assert_fixture(ProbeHarness.redis.delete_count.zero?, "unowned ambiguous claim was deleted")
expect_probe_state("probe-already-running")
assert_fixture(
  ProbeHarness.redis.get(MochiriiEmailMetadata::HEALTH_STATE_KEY) == retained_claim,
  "competing caller changed the retained owner",
)
ProbeHarness.clock = 90.0
new_preparing = MochiriiEmailMetadata.claim_health_probe!(ProbeHarness::FIXED_NONCE, 90)
assert_fixture(
  new_preparing == "preparing:" + ProbeHarness::FIXED_NONCE,
  "direct NX claim did not expire and replace the ambiguous owner",
)
MochiriiEmailMetadata.clear_health_probe!(ProbeHarness::FIXED_NONCE, nil)
assert_health_state_absent

# Two callers cannot overlap. The second refuses the first preparing generation
# without cleanup; the first then completes normally.
ProbeHarness.reset(mode: :complete, enqueue_hold: true)
thread_result = nil
thread_error = nil
first =
  Thread.new do
    begin
      thread_result = MochiriiEmailMetadata.verify_sidekiq_processing!
    rescue StandardError => error
      thread_error = error
    end
  end
ProbeHarness.enqueue_entered.pop
first_state = ProbeHarness.redis.get(MochiriiEmailMetadata::HEALTH_STATE_KEY)
expect_probe_state("probe-already-running")
assert_fixture(
  ProbeHarness.redis.get(MochiriiEmailMetadata::HEALTH_STATE_KEY) == first_state,
  "overlapping caller changed the first caller's state",
)
ProbeHarness.enqueue_release << true
first.join
assert_fixture(thread_error.nil? && thread_result == true, "first overlapping caller did not complete")
assert_owned_cleanup

# If enqueue itself stalls beyond the grace lease, the caller cannot bind or
# publish a false pending state after expiry.
ProbeHarness.reset(mode: :backlog, enqueue_hold: true)
expired_error = nil
expired =
  Thread.new do
    begin
      MochiriiEmailMetadata.verify_sidekiq_processing!
    rescue StandardError => error
      expired_error = error
    end
  end
ProbeHarness.enqueue_entered.pop
ProbeHarness.clock = 90.0
assert_health_state_absent
ProbeHarness.enqueue_release << true
expired.join
assert_fixture(
  expired_error.is_a?(MochiriiEmailMetadata::SidekiqProbeError) &&
    expired_error.state == "marker-mismatch" &&
    expired_error.cause.nil?,
  "expired pre-bind caller did not fail closed",
)
assert_health_state_absent

# Missing state fails as a mismatch. Foreign state is preserved because cleanup
# is conditional on the exact generation and therefore reports cleanup-failed.
ProbeHarness.reset(mode: :missing_state)
expect_probe_state("marker-mismatch")
assert_owned_cleanup

ProbeHarness.reset(mode: :wrong_state)
expect_probe_state("cleanup-failed")
assert_fixture(
  ProbeHarness.redis.get(MochiriiEmailMetadata::HEALTH_STATE_KEY) == "completed:" + ProbeHarness::WRONG_JID,
  "foreign state was deleted by the wrong caller",
)

# Pending and started states retain conservative meaning at the unchanged
# 60-second observation deadline. They do not claim a queue/retry/dead cause.
ProbeHarness.reset(mode: :backlog)
expect_probe_state("job-not-started-before-timeout")
assert_fixture(ProbeHarness.clock == 60.0, "default probe observation window changed")
assert_owned_cleanup

ProbeHarness.reset(mode: :started_only)
expect_probe_state("job-started-without-completion")
assert_owned_cleanup

# A worker transition error publishes failed, re-raises only a fixed retry error,
# and reaches the verifier only as job-reported-failure.
ProbeHarness.reset(mode: :job_exception)
expect_probe_state("job-reported-failure")
assert_fixture(
  ProbeHarness.worker_exception.is_a?(MochiriiEmailMetadata::SidekiqProbeJobError) &&
    ProbeHarness.worker_exception.message == "Mochirii Sidekiq processing probe job requires retry" &&
    ProbeHarness.worker_exception.cause.nil?,
  "worker exception did not become the fixed cause-free retry error",
)
assert_fixture(
  ProbeHarness.redis.history.any? { |state| state == "failed:" + ProbeHarness.jid },
  "worker failure state was not published",
)
assert_owned_cleanup

# A same-JID retry resumes a durable started state; an expired/cleaned old JID or
# a different generation cannot recreate or mutate state.
ProbeHarness.reset
ProbeHarness.redis.force_state("started:" + ProbeHarness::VALID_JID)
ProbeHarness.execute_job(ProbeHarness::VALID_JID)
assert_fixture(
  ProbeHarness.redis.get(MochiriiEmailMetadata::HEALTH_STATE_KEY) == "completed:" + ProbeHarness::VALID_JID,
  "same-JID retry did not resume started state",
)
ProbeHarness.redis.force_absent
ProbeHarness.execute_job(ProbeHarness::VALID_JID)
assert_health_state_absent
ProbeHarness.redis.force_state("pending:" + ProbeHarness::VALID_JID, lease_seconds: 1)
ProbeHarness.clock = 1.0
ProbeHarness.execute_job(ProbeHarness::VALID_JID)
assert_health_state_absent
ProbeHarness.redis.force_state("pending:" + ProbeHarness::SECOND_JID)
ProbeHarness.execute_job(ProbeHarness::VALID_JID)
assert_fixture(
  ProbeHarness.redis.get(MochiriiEmailMetadata::HEALTH_STATE_KEY) == "pending:" + ProbeHarness::SECOND_JID,
  "old JID changed a newer pending generation",
)
ProbeHarness.redis.force_state("preparing:" + ProbeHarness::FIXED_NONCE)
ProbeHarness.execute_job(ProbeHarness::VALID_JID)
assert_fixture(
  ProbeHarness.worker_exception.is_a?(MochiriiEmailMetadata::SidekiqProbeJobError),
  "unbound worker did not request fixed retry",
)
assert_fixture(
  ProbeHarness.redis.get(MochiriiEmailMetadata::HEALTH_STATE_KEY) == "preparing:" + ProbeHarness::FIXED_NONCE,
  "old JID changed a newer preparing generation",
)

# Lua results are exact integers, never Ruby truthiness. The exact script returns
# zero only for absence and one only after deleting the caller's own state;
# nil, raised, or foreign results fail.
ProbeHarness.reset
assert_fixture(
  MochiriiEmailMetadata.clear_health_probe!(ProbeHarness::FIXED_NONCE, ProbeHarness::VALID_JID).nil?,
  "absent cleanup result zero was not accepted",
)
ProbeHarness.redis.force_state("pending:" + ProbeHarness::VALID_JID)
assert_fixture(
  MochiriiEmailMetadata.clear_health_probe!(ProbeHarness::FIXED_NONCE, ProbeHarness::VALID_JID).nil?,
  "owned cleanup result one was not accepted",
)
assert_health_state_absent
ProbeHarness.reset(takeover_after_delete: true)
ProbeHarness.redis.force_state("pending:" + ProbeHarness::VALID_JID)
assert_fixture(
  MochiriiEmailMetadata.clear_health_probe!(ProbeHarness::FIXED_NONCE, ProbeHarness::VALID_JID).nil?,
  "atomic cleanup rejected a valid immediate ownership handoff",
)
assert_fixture(
  ProbeHarness.redis.get(MochiriiEmailMetadata::HEALTH_STATE_KEY) == "pending:" + ProbeHarness::SECOND_JID,
  "old cleanup changed the immediately acquired generation",
)
ProbeHarness.redis.force_state("pending:" + ProbeHarness::SECOND_JID)
begin
  MochiriiEmailMetadata.clear_health_probe!(ProbeHarness::FIXED_NONCE, ProbeHarness::VALID_JID)
  raise ProbeHarness::FixtureError, "foreign Lua cleanup result was accepted"
rescue MochiriiEmailMetadata::SidekiqProbeError => error
  assert_state_only(error, "cleanup-failed")
end
assert_fixture(
  ProbeHarness.redis.get(MochiriiEmailMetadata::HEALTH_STATE_KEY) == "pending:" + ProbeHarness::SECOND_JID,
  "foreign cleanup state was changed",
)
ProbeHarness.delete_override = :nil
begin
  MochiriiEmailMetadata.clear_health_probe!(ProbeHarness::FIXED_NONCE, ProbeHarness::VALID_JID)
  raise ProbeHarness::FixtureError, "nil Lua cleanup result was accepted"
rescue MochiriiEmailMetadata::SidekiqProbeError => error
  assert_state_only(error, "cleanup-failed")
end
ProbeHarness.delete_override = :raise
begin
  MochiriiEmailMetadata.clear_health_probe!(ProbeHarness::FIXED_NONCE, ProbeHarness::VALID_JID)
  raise ProbeHarness::FixtureError, "raised Lua cleanup result was accepted"
rescue MochiriiEmailMetadata::SidekiqProbeError => error
  assert_state_only(error, "cleanup-failed")
end

# A caller cleanup refusal retains its exact completed state under the original
# lease instead of deleting blindly.
ProbeHarness.reset(mode: :complete, delete_override: :minus_one)
expect_probe_state("cleanup-failed")
assert_cleanup_attempted
assert_fixture(
  ProbeHarness.redis.get(MochiriiEmailMetadata::HEALTH_STATE_KEY) == "completed:" + ProbeHarness.jid,
  "cleanup refusal did not retain the exact completed state",
)

puts "Sidekiq processing probe hostile fixture passed."
