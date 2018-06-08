DOCKER!



A docker image has a few parts:
* A base 'scratch' filesystem to write on
* A base filesystem, usually based on some linux stuff. Things like /boot, /opt, /etc, /bin, ect.. Need these things to start up!
* The application our image is made for. This could be something like python, sql, a webserver, ect..
* Any code we upload. This can be specified on the command line as well as the final dockerfile in the process.
Whew! the nice part about breaking this into pieces is that
1) I don't have to make a new base filesystem, or python or whatever when I am using docker. Reusability!
2) Common components can be shared between docker containers. This HUGELY reduces the actual footprint of docker containers.



While a VM creates its own kernel, virtual memory, ect, and runs in its own space. Docker will run a container as a process natively (at least on linux it does) but within its own filesystem. To share things you can mount/share volumes.


image - a package contining all the code, libraries, configs, ect, to run the application

container - runtime instantiantiation of an image.



'docker info' - give info about current containers and docker

'docker run IMAGE' - start up a container
-d option runs in detached mode. 'docker 


image - 
'docker image ls' - List downloaded and created images

container - 
'docker container ls' - list running containers

task - A single container, which is running in some service


service - Contains/controlls 1 or more containers of the same image. Can be thought of as "a container in production", as you will probably start your containers as services. Can define the amount of resources granted, number of copies of the container, ect.
'docker service ls'


swarm - A group of machines all running docker, working together. Each machine is a node. Swarm managers are machines which can execute commands for the swarm.
'docker swarm init'

node - A machine in a swarm network
'docker node ls'


stack - A group of services running together. They may share dependencies. 






