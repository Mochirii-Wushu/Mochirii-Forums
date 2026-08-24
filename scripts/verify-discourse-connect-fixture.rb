# frozen_string_literal: true

# Disposable-only database assertion for the built-in consumer. It emits no
# member identifier or payload.

raise "Consumer verifier is fixture-only" unless ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"] == "true"

record = SingleSignOnRecord.find_by(external_id: "mochirii-stage4-consumer-fixture")
raise "Fixture external identity was not persisted" if record.nil?
user = record.user
raise "Fixture consumer user is absent" if user.nil?
raise "Fixture consumer username changed" unless user.username == "mochirii-s4-test"
raise "Fixture consumer email changed" unless user.email == "stage4-fixture@forums.mochirii.com"
raise "Fixture consumer user is not active" unless user.active?
raise "Fixture consumer user is staged" if user.staged?
raise "Fixture consumer unexpectedly became staff" if user.staff?
raise "Fixture consumer record is not unique" unless SingleSignOnRecord.where(external_id: record.external_id).one?

puts "Built-in consumer persistence passed."
