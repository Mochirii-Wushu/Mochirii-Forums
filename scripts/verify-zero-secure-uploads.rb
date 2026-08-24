# frozen_string_literal: true

count = Upload.where(secure: true).count
raise "Secure uploads exist; do not enable or migrate object storage" unless count.zero?
puts "Secure-upload precondition passed."
