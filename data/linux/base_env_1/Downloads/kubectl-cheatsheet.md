# kubectl cheatsheet

## Context
```
kubectl config get-contexts
kubectl config use-context <name>
kubectl config set-context --current --namespace=<ns>
```

## Pods
```
kubectl get pods -n <ns>
kubectl describe pod <name> -n <ns>
kubectl logs <pod> -n <ns> --tail=100 -f
kubectl exec -it <pod> -n <ns> -- /bin/sh
```

## Deployments
```
kubectl get deployments -n <ns>
kubectl rollout status deployment/<name> -n <ns>
kubectl rollout restart deployment/<name> -n <ns>
kubectl scale deployment/<name> --replicas=3 -n <ns>
```

## Debugging
```
kubectl get events --sort-by='.lastTimestamp' -n <ns>
kubectl top pods -n <ns>
kubectl get pods -n <ns> -o wide
kubectl describe node <node-name>
```

## Port forwarding
```
kubectl port-forward svc/<name> 8080:80 -n <ns>
kubectl port-forward pod/<name> 5432:5432 -n <ns>
```
