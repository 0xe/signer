Vagrant.configure("2") do |config|
  config.vm.box = "debian/testing64"
  config.vm.provider "virtualbox" do |v|
    v.memory = 4096
    v.cpus = 4
  end
  config.vm.synced_folder "", "/code/", owner: "vagrant", group: "vagrant"
  config.vm.provision "bootstrap", type: "shell" do |s|
    s.inline = "apt-get -y install libjansson-dev libpcre3-dev zlib1g-dev"
  end
end
