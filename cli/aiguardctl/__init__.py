"""aiguardctl: upgrade a Shadow AI Guard deployment from your own machine.

The portal says a newer release exists and approves this command; the
command applies the upgrade with the operator's own kubeconfig or Docker
context and reports each step back so the portal can show it. Nothing in
the platform gains a right over the deployment. See SECURITY.md,
"Upgrading", in the project repository.
"""
__version__ = "0.29.0"
