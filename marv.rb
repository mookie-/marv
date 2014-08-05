#!/usr/bin/ruby
#
#   * ----------------------------------------------------------------------------
#   * "THE BEER-WARE LICENSE" (Revision 42):
#   * <kim@maisspace.org> wrote this file. As long as you retain this notice you
#   * can do whatever you want with this stuff. If we meet some day, and you think
#   * this stuff is worth it, you can buy me a beer in return Kim
#   * ----------------------------------------------------------------------------
#

require 'yaml'
require 'rubygems'
require 'right_aws'
require 'thread'

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

def dump_mysql(host, username, password, database, sslca, tables, backup_dir, crypt_passfile, dump_path, compress)
  sslca = '--ssl-ca=' + sslca if sslca
  if compress
    compress = "|#{compress}"
  end
  if crypt_passfile
    crypt_passfile = "|/usr/bin/openssl enc -aes-256-cbc -salt -pass file:#{crypt_passfile}"
  end
  command = "/usr/bin/mysqldump #{sslca} -h\"#{host}\" -u\"#{username}\" -p\"#{password}\" #{database} #{tables} #{compress} #{crypt_passfile} > #{dump_path}"
end

def dump_psql(host, username, password, database, tables, backup_dir, crypt_passfile, dump_path, compress)
  if compress
    compress = "|#{compress}"
  end
  if crypt_passfile
    crypt_passfile = "|/usr/bin/openssl enc -aes-256-cbc -salt -pass file:#{crypt_passfile}"
  end
  tables = '--table' + tables if tables
  command = "PGPASSWORD=#{password} /usr/bin/pg_dump -h\"#{host}\" #{tables} -U\"#{username}\" #{database} #{compress} #{crypt_passfile} > #{dump_path}"
end

def dump_database(type, host, username, password, database, sslca, tables, backup_dir, crypt_passfile, s3_bucket = nil, s3_access_key = nil, s3_secret_access_key = nil, compress = 'bzip2')
  log("start dump #{type} host=#{host} db=#{database} tables=#{tables} to #{backup_dir}")
  tablestring = '-tables-' + tables.gsub(/ /, '_') if tables
  dump_filename = "#{type}-#{host}-#{database}#{tablestring}-#{Time.now.strftime("%Y_%m_%d-%H_%M_%S")}.sql"
  dump_path = "#{backup_dir}/#{dump_filename}"
  dump_path = dump_path + '.' + compress if compress
  dump_path = dump_path + '.enc' if crypt_passfile
  case type
  when "mysql"
    command = dump_mysql(host, username, password, database, sslca, tables, backup_dir, crypt_passfile, dump_path, compress)
  when "psql"
    command = dump_psql(host, username, password, database, tables, backup_dir, crypt_passfile, dump_path, compress)
  else
    log("databasetype #{type} not available", 'error')
  end
  `#{command}`
  if File.exists? dump_path
    log("finish dump #{type} host=#{host} db=#{database} tables=#{tables} to #{backup_dir}")
  else
    log("dump failed failed #{dump_filename}", 'error')
  end
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

def local_dir(path, backup_dir, crypt_passfile, s3_bucket, s3_access_key, s3_secret_access_key, prefix)
  log("start backup dir #{path} to #{backup_dir}")
  directory_name = File.basename(path)
  prefix = prefix + "-" if prefix
  directory_path = "#{backup_dir}/#{prefix}#{directory_name}-#{Time.now.strftime("%Y_%m_%d-%H_%M_%S")}.tar.bz2"
  if crypt_passfile
    crypt_passfile = "|/usr/bin/openssl enc -aes-256-cbc -salt -pass file:#{crypt_passfile}"
    directory_path = directory_path + '.enc'
  end
  `/bin/tar -cj #{path} #{crypt_passfile} > #{directory_path}`
  log("Backup of #{directory_path} failed", 'error') unless File.exists? directory_path
  if s3_bucket && s3_access_key && s3_secret_access_key
    to_s3(directory_path, s3_bucket, s3_access_key, s3_secret_access_key)
  end
  log("finish backup dir #{path} to #{backup_dir}")
end

def local_subdir(path, backup_dir, crypt_passfile, s3_bucket, s3_access_key, s3_secret_access_key)
  log("start subdir backup of #{path} to #{backup_dir}")
  subdirs = `ls -1 #{path}`.split("\n")
  subdirs.each do |subdir|
    backup = Hash.new
    backup['type'] = 'local_dir'
    backup['path'] = path + "/" + subdir
    backup['backup_dir'] = backup_dir
    backup['crypt_passfile'] = crypt_passfile
    backup['s3_bucket'] = s3_bucket
    backup['s3_access_key'] = s3_access_key
    backup['s3_secret_access_key'] = s3_secret_access_key
    backup['prefix'] = File.basename(path)
    @queue << backup
  end
end

def to_s3(path, bucket, access_key, secret_access_key)
  log("start s3 upload for file #{path}")
  s3 = RightAws::S3.new(access_key, secret_access_key)
  begin
    key = RightAws::S3::Key.create(s3.bucket(bucket), File.basename(path))
    key.put_multipart(File.open(path), nil, {}, 500*1024*1024)
    log("finish s3 upload for file #{path}")
  rescue RightAws::AwsError
    log("failed s3 upload for file #{path}", 'error')
    backup = Hash.new
    backup['path'] = path
    backup['bucket'] = bucket
    backup['access_key'] = access_key
    backup['secret_access_key'] = secret_access_key
    @queue << backup
    log("added s3 upload for file #{path} to queue")
  end
end

log("start marv backup")

config_path = ARGV[0] || 'config.yaml'

config = YAML::load(File.read(config_path))

@queue = Queue.new

config['backup'].each do |type,values|
  backup = Hash.new
  values.each do |name,value|
    backup["#{name}"] = value
  end
  @queue << backup
end

until @queue.empty?
  backup = @queue.pop(true) rescue nil
  if backup
    case backup['type']
    when "mysql"
      mysql(backup['host'], backup['user'], backup['pw'], backup['db'], backup['sslca'], backup['tables'], backup['backup_dir'], backup['crypt_passfile'], backup['s3_bucket'], backup['s3_access_key'], backup['s3_secret_access_key'])
    when "psql"
      psql(backup['host'], backup['user'], backup['pw'], backup['db'], backup['tables'], backup['backup_dir'], backup['crypt_passfile'], backup['s3_bucket'], backup['s3_access_key'], backup['s3_secret_access_key'])
    when "local_dir"
      local_dir(backup['path'], backup['backup_dir'], backup['crypt_passfile'], backup['s3_bucket'], backup['s3_access_key'], backup['s3_secret_access_key'], backup['prefix'])
    when "local_subdir"
      local_subdir(backup['path'], backup['backup_dir'], backup['crypt_passfile'], backup['s3_bucket'], backup['s3_access_key'], backup['s3_secret_access_key'])
    when "s3_upload"
      to_s3(backup['path'], backup['bucket'], backup['access_key'], backup['secret_access_key'])
    else
      log("backuptype #{backup['type']} not available", 'error')
    end
  end
end
