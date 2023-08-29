#!/bin/bash

# unfortunately all by hand.

kubectl delete ns supervisor-ns
kubectl delete ns concierge-ns
kubectl delete packageinstall concierge-package-install
kubectl delete packageinstall supervisor-package-install
