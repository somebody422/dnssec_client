https://www.vagrantup.com/intro/getting-started/index.html

Vagrant will take configuration info and create a headless virtual machine! This is useful because you can manage in the configuration exactly what versions of everthing. Anyone can download your vagrant 'box' and have the same starting place as everyone else. Could use this to develop with a guarenteed environment, or to test on a "user" environment.

Vagrantfile - Configuration file. The default just specifies which box to use and that is it! This file should be in the root directory of the project, some configuration options will use relative paths from this directory.

Box - a packaged up environment. Can create a custom box then distribute it.

Provisioning - Scripts that configure the environment. Only run when the vm starts up and when the user calls 'vagrant provision'


'vagrant init BOX': initialize (but don't start!) a virtual env with box BOX
'vagrant up': start the vm
'vagrant suspend' pause the vm
'vagrant halt' turn the vm off
'vagrant destroy' Nuke the running VM from orbit. does not get rid of the box or vagrantfile
