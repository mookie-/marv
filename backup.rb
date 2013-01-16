#!/usr/bin/ruby

require 'thread'
require 'yaml'
require 'rubygems'
require 'right_aws'

def log(message, type=nil)
  case type
  when 'error'
    puts "#{Time.now} Marv Error Log: #{message}"
  when 'debug'
    puts "#{Time.now} Marv Debug Log: #{message}"
  else
    puts "#{Time.now} Marv Log: #{message}"
  end
end

def crypt(file_path,crypt_passfile)
  log("start crypt #{file_path}")
  if File.exists? crypt_passfile
    crypt_file_path = "#{file_path}.enc"
    `/usr/bin/openssl enc -aes-256-cbc -salt -in #{file_path} -out #{crypt_file_path} -pass file:#{crypt_passfile}`
    if File.exists? crypt_file_path
      File.unlink(file_path)
      log("finish crypt #{file_path}")
      crypt_file_path
    else
      log("Encryption of file #{crypt_file_path} failed", 'error')
    end
  else
    log("Encryption of file #{crypt_file_path} failed. Passfile not found #{crypt_passfile}", 'error')
  end
end

def dump_mysql(host, username, password, database, sslca, tables, backup_dir, crypt_passfile, dump_path)
  sslca = '--ssl-ca=' + sslca if sslca
  command = "/usr/bin/mysqldump #{sslca} -h\"#{host}\" -u\"#{username}\" -p\"#{password}\" #{database} #{tables} -r #{dump_path}"
end

def dump_psql(host, username, password, database, tables, backup_dir, crypt_passfile, dump_path)
  tables = '--table' + tables if tables
  command = "PGPASSWORD=#{password} /usr/bin/pg_dump -h\"#{host}\" #{tables} -U\"#{username}\" #{database} -f #{dump_path}"
end

def dump_database(type, host, username, password, database, sslca, tables, backup_dir, crypt_passfile, s3_bucket = nil, s3_access_key = nil, s3_secret_access_key = nil)
  log("start dump #{type} host=#{host} db=#{database} tables=#{tables} to #{backup_dir}")
  tablestring = '-tables-' + tables.gsub(/ /, '_') if tables
  dump_filename = "#{type}-#{host}-#{database}#{tablestring}-#{Time.now.strftime("%Y_%m_%d-%H_%M_%S")}.sql"
  dump_path = "#{backup_dir}/#{dump_filename}"
  case type 
  when "mysql"
    command = dump_mysql(host, username, password, database, sslca, tables, backup_dir, crypt_passfile, dump_path)
  when "psql"
    command = dump_psql(host, username, password, database, tables, backup_dir, crypt_passfile, dump_path)
  else
    log("databasetype #{type} not available", 'error')
  end
  `#{command}`
  if File.exists? dump_path
    log("finish dump #{type} host=#{host} db=#{database} tables=#{tables} to #{backup_dir}")
    `/bin/bzip2 #{dump_path}`
    dump_path = "#{dump_path}.bz2"
  else
    log("MySQLdump failed #{dump_filename}", 'error')
  end
  dump_path = crypt(dump_path,crypt_passfile) if crypt_passfile
  if s3_bucket && s3_access_key && s3_secret_access_key
    to_s3(dump_path, s3_bucket, s3_access_key, s3_secret_access_key)
  end
end

def mysql(host, username, password, database, sslca, tables, backup_dir, crypt_passfile, s3_bucket, s3_access_key, s3_secret_access_key)
  if database == :all
    databases = `/usr/bin/mysql #{sslca} -h"#{host}" -u"#{username}" -p"#{password}" -Bse 'show databases'`.split("\n")
    databases.delete('information_schema')
    databases.delete('performance_schema')
    databases.each do |database|
      dump_database('mysql', host, username, password, database, sslca, tables, backup_dir, crypt_passfile, s3_bucket, s3_access_key, s3_secret_access_key)
    end
  else
    dump_database('mysql', host, username, password, database, sslca, tables, backup_dir, crypt_passfile, s3_bucket, s3_access_key, s3_secret_access_key)
  end
end

def psql(host, username, password, database, tables, backup_dir, crypt_passfile, s3_bucket, s3_access_key, s3_secret_access_key)
  if database == :all
    log("automated dump of all psql databases is not implemented yet", 'error')
#    databases = `foo`
#    databases.each do |database|
#      dump_database('psql', host, username, password, database, tables, backup_dir, crypt_passfile)
#    end
  else
    dump_database('psql', host, username, password, database, nil, tables, backup_dir, crypt_passfile, s3_bucket, s3_access_key, s3_secret_access_key)
  end
end

def local_dir(path, backup_dir, crypt_passfile, s3_bucket, s3_access_key, s3_secret_access_key)
  log("start backup dir #{path} to #{backup_dir}")
  directory_name = File.basename(path)
  directory_path = "#{backup_dir}/#{directory_name}-#{Time.now.strftime("%Y_%m_%d-%H_%M_%S")}.tar.bz2"
  `/bin/tar -cjf #{directory_path} #{path}`
  log("Backup of #{directory_path} failed", 'error') unless File.exists? directory_path
  crypt(directory_path,crypt_passfile) if crypt_passfile
  log("finish backup dir #{path} to #{backup_dir}")
end

def to_s3(path, bucket, access_key, secret_access_key)
  log("start s3 upload for file #{path}")
  s3 = RightAws::S3Interface.new(access_key, secret_access_key)
  s3.put(bucket, File.basename(path), File.open(path))
  log("finish s3 upload for file #{path}")
end

log("start marv backup")

config_path = ARGV[0] || 'config.yaml'

config = YAML::load(File.read(config_path))

queue = Queue.new
threads = []

config['backup'].each do |type,values|
  backup = Hash.new
  values.each do |name,value|
    backup["#{name}"] = value
  end
  queue << backup
end

log("backup run with #{config['threads']} threads")

config['threads'].times do
  threads << Thread.new do
    until queue.empty?
      backup = queue.pop(true) rescue nil
      if backup
        case backup['type']
        when "mysql"
          mysql(backup['host'], backup['user'], backup['pw'], backup['db'], backup['sslca'], backup['tables'], backup['backup_dir'], backup['crypt_passfile'], backup['s3_bucket'], backup['s3_access_key'], backup['s3_secret_access_key'])
        when "psql"
          psql(backup['host'], backup['user'], backup['pw'], backup['db'], backup['tables'], backup['backup_dir'], backup['crypt_passfile'], backup['s3_bucket'], backup['s3_access_key'], backup['s3_secret_access_key'])
        when "local_dir"
          local_dir(backup['path'], backup['backup_dir'], backup['crypt_passfile'], backup['s3_bucket'], backup['s3_access_key'], backup['s3_secret_access_key'])
        else
          log("backuptype #{backup['type']} not available", 'error')
        end
      end
    end
  end
end

threads.each { |t| t.join }
