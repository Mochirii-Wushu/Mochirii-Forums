# frozen_string_literal: true

checks = {
  positive_id_user_absent: User.where("id > 0").none?,
  member_post_absent: Post.where("user_id > 0").none?,
  member_topic_absent: Topic.where("user_id > 0").none?,
  upload_absent: Upload.none?,
  api_key_absent: ApiKey.none?,
  user_api_key_absent: UserApiKey.none?,
  recovery_marker_absent: PluginStore.get("mochirii-recovery", "repository_commit").nil?,
  recovery_upload_marker_absent: PluginStore.get("mochirii-recovery", "normal_upload_marker").nil?,
}

raise "Clean-target disaster restore guard failed" if checks.value?(false)

puts "clean-disaster-target=true"
