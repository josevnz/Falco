# Falco (with Prometheus and Grafana integrations)

I decided to share the code and configuration files I used on the [Securing mixed clouds using Falco, Prometheus, Grafana and Docker](tutorial/README.md) tutorial.

The whole idea was to document my experience of learning Falco and its integration with other frameworks like Prometheus and Grafana.

# Installation/ setup

You can clone the git repository and install in development mode:

```shell
python -m venv ~/virtualenv/Falco
. ~/virtualenv/Falco/bin/activate
pip install --editable .
```

# Generating the diagrams

After all the dependencies are installed it should be easy to do:

```shell
falco_diagram.py tutorial/falco_monitoring
```

# Experimenting, building the package

If you want to create both the source distribution and wheel you can do this:

```shell
python -m venv ~/virtualenv/Falco
. ~/virtualenv/Falco/bin/activate
python -m build
```

Then you can copy/ install to another machine.

I recommend you take a look at the [Tutorial](tutorial/README.md) to get the full picture and overview of the other scripts included on this distribution. 

## Tutorial files are not packaged when I run ```python -m build```

It is on purpose, I only want to package the scripts on the distribution. The best way to read the tutorial is by cloning the
distribution (wich you probably did if you are reading this)

# Last bits
I hope you enjoy this code, please [report any bugs or leave your comments](https://github.com/josevnz/Falco/issues).

--Jose