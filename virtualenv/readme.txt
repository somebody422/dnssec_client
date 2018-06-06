PLEASE NOTE: the actual virtualenv environment is not in git because it causes problems. just do 'virtualenv env1' to make one


There are actually a ton of python environment management thingies, but this is usually the one people think about first.

SO about different python environment/package manager things. there are quite a few
https://stackoverflow.com/questions/41573587/what-is-the-difference-between-venv-pyvenv-pyenv-virtualenv-virtualenvwrappe




virtualenv is a SUPER SIMPLE command/concept, but has wonderful uses/implications.

'virtualenv DIR' will create:
DIR/
DIR/bin - lots of goodies in here. The python executables, pip, easy_install, activation script
DIR/include
DIR/lib - populated with required lib files



To start up the virtual env, from bash, run 'source PATH/TO/DIR/bin/activate'. This does a few things including:
* Add DIR/bin to the front of the path. This tries to guarentee that exe and scripts from this env will be run first.
* adds some bash variables and functions into the running shell including deactivate() and pydoc()
* change the PS1 prompt to reflect that we are now "in" a virtualenv

'deactivate' will leave a virtualenv

to delte an environment, make sure you are not in it, then just remove DIR




That's it!
