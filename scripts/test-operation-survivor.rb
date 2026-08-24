# frozen_string_literal: true

require "fileutils"
require "tmpdir"

ROOT = File.expand_path("..", __dir__)
HOST_SCANS = {
  "scripts/host-deploy.sh" => 1,
  "scripts/host-backup.sh" => 1,
  "scripts/host-restore-validate.sh" => 3,
  "scripts/host-break-glass-admin.sh" => 1,
  ".github/workflows/disposable-bootstrap.yml" => 1,
}.freeze
GENERATED_HOST_SCANS = {
  "scripts/verify-discourse-connect.py" => 1,
}.freeze

good_source = ['File.binread(path).split("', 92.chr, '0", -1).include?(marker)'].join
bad_source = ['File.binread(path).split("', 92.chr, 92.chr, '0", -1).include?(marker)'].join
HOST_SCANS.each do |relative, expected_count|
  source = File.binread(File.join(ROOT, relative))
  raise "#{relative} survivor scan count differs" unless source.scan(good_source).length == expected_count
  raise "#{relative} retained a literal backslash-zero split" if source.include?(bad_source)
end
generated_good_source = ['File.binread(path).split("', 92.chr, 92.chr, '0", -1).include?(marker)'].join
generated_bad_source = ['File.binread(path).split("', 92.chr, 92.chr, 92.chr, 92.chr, '0", -1).include?(marker)'].join
GENERATED_HOST_SCANS.each do |relative, expected_count|
  source = File.binread(File.join(ROOT, relative))
  raise "#{relative} generated survivor scan count differs" unless source.scan(generated_good_source).length == expected_count
  raise "#{relative} generates a literal backslash-zero split" if source.include?(generated_bad_source)
end

def marked_process?(paths, token)
  marker = "MOCHIRII_OPERATION_TOKEN=#{token}"
  paths.any? do |path|
    begin
      File.binread(path).split("\0", -1).include?(marker)
    rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
      false
    end
  end
end

Dir.mktmpdir("mochirii-operation-survivor-") do |root|
  marked = File.join(root, "101", "environ")
  unmarked = File.join(root, "202", "environ")
  FileUtils.mkdir_p(File.dirname(marked))
  FileUtils.mkdir_p(File.dirname(unmarked))
  token = "a" * 32
  marker = "MOCHIRII_OPERATION_TOKEN=#{token}"
  File.binwrite(marked, ["PATH=/usr/bin", marker, "HOME=/var/www/discourse", ""].join("\0"))
  File.binwrite(unmarked, ["PATH=/usr/bin", "MOCHIRII_OPERATION_TOKEN=#{'b' * 32}", ""].join("\0"))
  paths = [marked, unmarked, File.join(root, "303", "environ")]
  raise "Actual NUL-delimited marked survivor was missed" unless marked_process?(paths, token)
  raise "Unmarked operation was reported as a survivor" if marked_process?(paths, "c" * 32)
  if File.binread(marked).split("\\0", -1).include?(marker)
    raise "Hostile fixture no longer distinguishes literal backslash-zero"
  end
end

puts "Operation survivor NUL fixture passed."
