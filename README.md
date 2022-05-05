# How to enforce authorization policies using Istio's Egress Gateway

An Istio Egress gateway is just another envoy instance similar to the Ingress with the purpose to control outbound traffic. Istio uses ingress and egress gateways to configure load balancers executing at the edge of a service mesh. An ingress gateway allows you to define entry points into the mesh that all incoming traffic flows through. Egress gateway is a symmetrical concept; it defines exit points from the mesh. Egress gateways allow you to apply Istio features, for example, monitoring and route rules, to traffic exiting the mesh.

This article describes how to enforce outbound authorization policies using Istio's Egress gateway in a similar matter when enforcing inbound policies. For this we use the `sleep` service in two separate namespaces within the mesh to access external services at Google and Yahoo.

***
NOTE: One important consideration to be aware of is that Istio cannot securely enforce that all egress traffic actually flows through the egress gateways. Istio only enables such flow through its sidecar proxies. If attackers bypass the sidecar proxy, they could directly access external services without traversing the egress gateway. Kubernetes network policies (see `network-policy.yaml` file) can be used to prevent outbound traffic at the cluster level, see https://istio.io/latest/docs/tasks/traffic-management/egress/egress-gateway/#additional-security-considerations.
***

## Before starting

Before starting you need:
- a kubernetes cluster
- istioctl 
- sleep service

## Istio install

```bash
istioctl install -y --set profile=demo --set meshConfig.outboundTrafficPolicy.mode=ALLOW_ANY
```

Notice the demo profile installs an instance of an Egress gateway and we are configuring the handling of external services by using the `outboundTrafficPolicy` option. `ALLOW_ANY` is the default option enabling access to outbound services and `REGISTRY_ONLY` gets the proxies to block access if the host is not defined in the service registry using the `ServiceEntry` resource. 

## Install the sleep service in the default namespace

```bash
kubectl apply -f https://raw.githubusercontent.com/istio/istio/master/samples/sleep/sleep.yaml
```

## Now install the sleep service in the otherns namespace

```bash
kubectl create ns otherns
```

Label the namespace for sidecar injection:
```bash
kubectl label ns otherns istio-injection=enabled
```
Apply the service resources:
```bash
kubectl apply -n otherns -f https://raw.githubusercontent.com/istio/istio/master/samples/sleep/sleep.yaml
```

## Export `sleep` pods name into variables

```bash
export SLEEP_POD1=$(kubectl get pod -l app=sleep -ojsonpath='{.items[0].metadata.name}')
```
```bash
export SLEEP_POD2=$(kubectl get pod -n otherns -l app=sleep -ojsonpath='{.items[0].metadata.name}')
```

## Test `sleep` accessing Google and Yahoo

```bash
kubectl exec $SLEEP_POD1 -it -- curl -I https://developers.google.com
```

You should expect a similar response like:
```
HTTP/2 200 
last-modified: Mon, 18 Apr 2022 19:50:38 GMT
content-type: text/html; charset=utf-8
set-cookie: _ga_devsite=GA1.3.17352200.1651777078; Expires=Sat, 04-May-2024 18:57:58 GMT; Max-Age=63072000; Path=/
content-security-policy: base-uri 'self'; object-src 'none'; script-src 'strict-dynamic' 'unsafe-inline' https: http: 'nonce-6YT4DgbNb9SFKpYNAAh6BVQ1HrIWUp' 'unsafe-eval'; report-uri https://csp.withgoogle.com/csp/devsite/v2
strict-transport-security: max-age=63072000; includeSubdomains; preload
x-frame-options: SAMEORIGIN
x-xss-protection: 0
x-content-type-options: nosniff
cache-control: no-cache, must-revalidate
expires: 0
pragma: no-cache
x-cloud-trace-context: 3943a8b1bdf28d721eae4f82696ba2c4
content-length: 142275
date: Thu, 05 May 2022 18:57:58 GMT
server: Google Frontend
```

Now the other service:
```bash
kubectl exec $SLEEP_POD2 -n otherns -it -- curl -I https://developer.yahoo.com
```

You should expect a similar response like:
```
HTTP/2 200 
referrer-policy: no-referrer-when-downgrade
strict-transport-security: max-age=15552000
x-frame-options: SAMEORIGIN
x-powered-by: Express
cache-control: private, max-age=0, no-cache
content-security-policy-report-only: default-src 'none'; connect-src 'self' *.yimg.com https://www.google-analytics.com *.yahoo.com *.doubleclick.net; font-src 'self' *.bootstrapcdn.com; frame-src 'self' *.soundcloud.com *.twitter.com; img-src 'self' data: *.yimg.com https://www.google-analytics.com *.yahoo.com https://www.google.com/ads/ga-audiences *.pendo.io *.twitter.com *.twimg.com; script-src 'self' 'nonce-25FqRrNIte3nmHy7Es/O4Q==' *.yimg.com https://www.google-analytics.com https://ssl.google-analytics.com *.github.com/flurrydev/ *.pendo.io *.twitter.com *.twimg.com; style-src 'self' 'unsafe-inline' *.yimg.com *.twitter.com *.twimg.com https://github.githubassets.com/assets/ *.bootstrapcdn.com; report-uri /csp-report
content-type: text/html; charset=utf-8
content-length: 61158
etag: W/"eee6-355CS9JqgK79WnB2sdI2zK9AvBw"
vary: Accept-Encoding
date: Thu, 05 May 2022 19:00:06 GMT
x-envoy-upstream-service-time: 2315
server: ATS
age: 3
expect-ct: max-age=31536000, report-uri="http://csp.yahoo.com/beacon/csp?src=yahoocom-expect-ct-report-only"
x-xss-protection: 1; mode=block
x-content-type-options: nosniff
```

If you want you can test the other other address on the other `sleep` pod. We can confirm the pods have outbound access to Google and Yahoo.

## Block outbound access 

```bash
istioctl install -y --set profile=demo --set meshConfig.outboundTrafficPolicy.mode=REGISTRY_ONLY
```

## Test `sleep` access again

```bash
kubectl exec $SLEEP_POD1 -it -- curl -I https://developers.google.com
```

You should expect a similar response like:
```
curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection to developers.google.com:443 
command terminated with exit code 35
```

Now the other service:
```bash
kubectl exec $SLEEP_POD2 -n otherns -it -- curl -I https://developer.yahoo.com
```

You should expect a similar response like:
```
curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection to developer.yahoo.com:443 
command terminated with exit code 35
```

The error is due to the new policy enforcing only services part of the registry are allowed for outbound traffic.

***
NOTE: There could be a slight delay on the configuration being propagated to the sidecars where the still allow access to the external services.
***

## Add the Google and Yahoo services to the mesh service registry

Add Google:
```bash
kubectl apply -f google-serviceentry.yaml
```

Notice the `exportTo: - "."` section of the service entry resource specifying that is only applicable to the current namespace where applied. You can also change this to `"*"` for all namespaces in the mesh.

Test access to the service:
```bash
kubectl exec $SLEEP_POD1 -it -- curl -I https://developers.google.com
```

You should expect a 200 response code now. But what if we test this `sleep` service to Yahoo?
```bash
kubectl exec $SLEEP_POD1 -it -- curl -I https://developer.yahoo.com
```

You should expect an error along the lines:
```
curl: (35) OpenSSL SSL_connect: Connection reset by peer in connection to developer.yahoo.com:443 
command terminated with exit code 35
```

This is because we only allowed outbound traffic to Google from the default namespace where the `SLEEP_POD1` lives. Any outbound traffic from `SLEEP_POD2` should still be blocked, lets enabled traffic to Google:
```bash
kubectl apply -n otherns -f google-serviceentry.yaml
```

You should expect a 200 response code from both pods:
```bash
kubectl exec $SLEEP_POD2 -n otherns -it -- curl -I https://developers.google.com
kubectl exec $SLEEP_POD1 -it -- curl -I https://developers.google.com
```

Notice how Yahoo is still blocked on both services. Enable traffic on the default namespace and test it:
```bash
kubectl apply -f yahoo-serviceentry.yaml
```
```bash
kubectl exec $SLEEP_POD1 -it -- curl -I https://developer.yahoo.com
```

Now on the `otherns` namespace:
```bash
kubectl apply -n otherns -f yahoo-serviceentry.yaml
```
```bash
kubectl exec $SLEEP_POD2 -n otherns -it -- curl -I https://developer.yahoo.com
```

You should expect a 200 response code from both pods.

## Getting the Egress gateway involved

So far by changing the outbound traffic policy to `REGISTRY_ONLY` we can enforce how our proxy sidecars allow outbound traffic from the mesh to the external hosts only defined with our Service Entry resources, but we haven't enforced any policies using the Egress gateway on how outbound traffic should flow. 

We are going to define two Virtual Services for each of the host we are using as examples, Yahoo and Google where the first one enforces all outbound traffic originated within the mesh to flow to the egress gateway and then another virtual services that allows the traffic from the egress to the actual hostname. This will ensure that we only allow outbound traffic from the egress gateway defined in our `AuthorizationPolicy` resource.