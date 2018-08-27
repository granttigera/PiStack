## On mac
```
brew install pv
brew install awscli
brew install wget
wget https://github.com/DieterReuter/image-builder-rpi64/releases/download/v20171013-172949/hypriotos-rpi64-v20171013-172949.img.zip
curl -LO https://github.com/hypriot/flash/releases/download/2.1.1/flash\nchmod +x flash
sudo mv flash /usr/local/bin/flash
flash --hostname master1 hypriotos-rpi64-v20171013-172949.img.zip
```

## Setup master OS
```
ssh pirate@master1.local
sudo su -
vi /etc/network/interfaces.d/eth0
allow-hotplug eth0
#iface eth0 inet dhcp
iface eth0 inet static
address 172.16.0.130
gateway 172.16.0.1
#google dns servers
domain_name_servers=8.8.8.8, 8.8.4.4

swapoff -a
apt-get update
apt-get -y install libnss-mdns avahi-utils
reboot
```

## Setup etcd
```
flash --hostname etcd1 ~/Downloads/hypriotos-rpi64-v20171013-172949.img.zip

ssh pirate@etcd1.local
sudo su -

vi /etc/network/interfaces.d/eth0
allow-hotplug eth0
#iface eth0 inet dhcp
iface eth0 inet static
address 172.16.0.131
gateway 172.16.0.1
#google dns servers
domain_name_servers=8.8.8.8, 8.8.4.4

swapoff -a
apt-get update
apt-get -y install libnss-mdns avahi-utils
reboot
```
```
ssh pirate@etcd1.local
sudo su -

mkdir -p /var/lib/etcd
groupadd -f -g 1501 etcd
useradd -c "Etcd key-value store user" -d /var/lib/etcd -s /bin/false -g etcd -u 1501 etcd
chown -R etcd:etcd /var/lib/etcd


curl -ksL 'https://github.com/coreos/etcd/releases/download/v3.2.24/etcd-v3.2.24-linux-arm64.tar.gz' | tar -xzvf -
cp etcd-v3.2.24-linux-arm64/etcd* /usr/local/bin

vi /etc/systemd/system/etcd.service
[Unit]
Description=etcd key-value store
Documentation=https://github.com/coreos/etcd

[Service]
Environment=ETCD_UNSUPPORTED_ARCH=arm64
User=etcd
Type=notify
ExecStart=/usr/local/bin/etcd --name=etcd0 --data-dir=/var/lib/etcd --initial-advertise-peer-urls=http://0.0.0.0:2380 --listen-peer-urls=http://0.0.0.0:2380 --listen-client-urls=http://0.0.0.0:2379 --advertise-client-urls=http://0.0.0.0:2379
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target

systemctl daemon-reload
systemctl enable etcd
systemctl start etcd.service
systemctl status -l etcd.service
```
## Install kubeadm on master1
```
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list
apt-get update && apt-get install -y kubelet=1.9.6-00 kubeadm=1.9.6-00 kubernetes-cni=0.6.0-00 kubectl=1.9.6-00
$ kubeadm token generate
5d69bd.0cf57423e604617f

vi config.yaml
apiVersion: kubeadm.k8s.io/v1alpha1
kind: MasterConfiguration
api:
  advertiseAddress: 172.16.0.130
  bindPort: 6443
etcd:
  endpoints:
  - "http://172.16.0.131:2379"
apiServerCertSANs:
- "172.16.0.130"
- "127.0.0.1"
networking:
  podSubnet: "192.168.0.0/16"
token: "5d69bd.0cf57423e604617f"
tokenTTL: "0"
kubernetesVersion: 1.9.6
```
```
kubeadm init --config=config.yaml
#kubeadm join --token 5d69bd.0cf57423e604617f 172.16.0.130:6443 --discovery-token-ca-cert-hash sha256:5df77e08ae592eebeb0afc8b6c0f5ad485ded073297fc1956b7b4ba867383e63
exit
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

## Setup node1
```
ssh pirate@node1.local
sudo su -

vi /etc/network/interfaces.d/eth0
allow-hotplug eth0
#iface eth0 inet dhcp
iface eth0 inet static
address 172.16.0.132
gateway 172.16.0.1
#google dns servers
domain_name_servers=8.8.8.8, 8.8.4.4
swapoff -a
apt-get update
apt-get -y install libnss-mdns avahi-utils
reboot
```
```
ssh pirate@node3.local
sudo su -

curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list
apt-get update && apt-get install -y kubelet=1.9.6-00 kubeadm=1.9.6-00 kubernetes-cni=0.6.0-00 kubectl=1.9.6-00
kubeadm join --token 5d69bd.0cf57423e604617f 172.16.0.130:6443 --discovery-token-ca-cert-hash sha256:5df77e08ae592eebeb0afc8b6c0f5ad485ded073297fc1956b7b4ba867383e63
```

## Setup node2
```
ssh pirate@node2.local
sudo su -

vi /etc/network/interfaces.d/eth0
allow-hotplug eth0
#iface eth0 inet dhcp
iface eth0 inet static
address 172.16.0.133
gateway 172.16.0.1
#google dns servers
domain_name_servers=8.8.8.8, 8.8.4.4
swapoff -a
apt-get update
apt-get -y install libnss-mdns avahi-utils
reboot
```
```
ssh pirate@node3.local
sudo su -

curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list
apt-get update && apt-get install -y kubelet=1.9.6-00 kubeadm=1.9.6-00 kubernetes-cni=0.6.0-00 kubectl=1.9.6-00
kubeadm join --token 5d69bd.0cf57423e604617f 172.16.0.130:6443 --discovery-token-ca-cert-hash sha256:5df77e08ae592eebeb0afc8b6c0f5ad485ded073297fc1956b7b4ba867383e63
```

## Setup node3
```
ssh pirate@node3.local
sudo su -

vi /etc/network/interfaces.d/eth0
allow-hotplug eth0
#iface eth0 inet dhcp
iface eth0 inet static
address 172.16.0.134
gateway 172.16.0.1
#google dns servers
domain_name_servers=8.8.8.8, 8.8.4.4
swapoff -a
apt-get update
apt-get -y install libnss-mdns avahi-utils
reboot
```
```
ssh pirate@node3.local
sudo su -

curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list
apt-get update && apt-get install -y kubelet=1.9.6-00 kubeadm=1.9.6-00 kubernetes-cni=0.6.0-00 kubectl=1.9.6-00
kubeadm join --token 5d69bd.0cf57423e604617f 172.16.0.130:6443 --discovery-token-ca-cert-hash sha256:5df77e08ae592eebeb0afc8b6c0f5ad485ded073297fc1956b7b4ba867383e63
```

##Install Calico
###Setup RBAC
```
kubectl apply -f https://docs.projectcalico.org/v3.2/getting-started/kubernetes/installation/rbac.yaml
```
```
vi calico.yaml

# Calico Version v3.2.1
# https://docs.projectcalico.org/v3.2/releases#v3.2.1
# This manifest includes the following component versions:
#   calico/node:v3.2.1
#   calico/cni:v3.2.1
#   calico/kube-controllers:v3.2.1

# This ConfigMap is used to configure a self-hosted Calico installation.
kind: ConfigMap
apiVersion: v1
metadata:
  name: calico-config
  namespace: kube-system
data:
  # Configure this with the location of your etcd cluster.
  etcd_endpoints: "http://172.16.0.131:2379"

  # If you're using TLS enabled etcd uncomment the following.
  # You must also populate the Secret below with these files.
  etcd_ca: ""   # "/calico-secrets/etcd-ca"
  etcd_cert: "" # "/calico-secrets/etcd-cert"
  etcd_key: ""  # "/calico-secrets/etcd-key"
  # Configure the Calico backend to use.
  calico_backend: "bird"

  # Configure the MTU to use
  veth_mtu: "1440"

  # The CNI network configuration to install on each node.  The special
  # values in this config will be automatically populated.
  cni_network_config: |-
    {
      "name": "k8s-pod-network",
      "cniVersion": "0.3.0",
      "plugins": [
        {
          "type": "calico",
          "log_level": "info",
          "etcd_endpoints": "__ETCD_ENDPOINTS__",
          "etcd_key_file": "__ETCD_KEY_FILE__",
          "etcd_cert_file": "__ETCD_CERT_FILE__",
          "etcd_ca_cert_file": "__ETCD_CA_CERT_FILE__",
          "mtu": __CNI_MTU__,
          "ipam": {
              "type": "calico-ipam"
          },
          "policy": {
              "type": "k8s"
          },
          "kubernetes": {
              "kubeconfig": "__KUBECONFIG_FILEPATH__"
          }
        },
        {
          "type": "portmap",
          "snat": true,
          "capabilities": {"portMappings": true}
        }
      ]
    }

---


# The following contains k8s Secrets for use with a TLS enabled etcd cluster.
# For information on populating Secrets, see http://kubernetes.io/docs/user-guide/secrets/
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: calico-etcd-secrets
  namespace: kube-system
data:
  # Populate the following files with etcd TLS configuration if desired, but leave blank if
  # not using TLS for etcd.
  # This self-hosted install expects three files with the following names.  The values
  # should be base64 encoded strings of the entire contents of each file.
  # etcd-key: null
  # etcd-cert: null
  # etcd-ca: null

---

# This manifest installs the calico/node container, as well
# as the Calico CNI plugins and network config on
# each master and worker node in a Kubernetes cluster.
kind: DaemonSet
apiVersion: extensions/v1beta1
metadata:
  name: calico-node
  namespace: kube-system
  labels:
    k8s-app: calico-node
spec:
  selector:
    matchLabels:
      k8s-app: calico-node
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  template:
    metadata:
      labels:
        k8s-app: calico-node
      annotations:
        # This, along with the CriticalAddonsOnly toleration below,
        # marks the pod as a critical add-on, ensuring it gets
        # priority scheduling and that its resources are reserved
        # if it ever gets evicted.
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      hostNetwork: true
      tolerations:
        # Make sure calico-node gets scheduled on all nodes.
        - effect: NoSchedule
          operator: Exists
        # Mark the pod as a critical add-on for rescheduling.
        - key: CriticalAddonsOnly
          operator: Exists
        - effect: NoExecute
          operator: Exists
      serviceAccountName: calico-node
      # Minimize downtime during a rolling upgrade or deletion; tell Kubernetes to do a "force
      # deletion": https://kubernetes.io/docs/concepts/workloads/pods/pod/#termination-of-pods.
      terminationGracePeriodSeconds: 0
      containers:
        # Runs calico/node container on each Kubernetes node.  This
        # container programs network policy and routes on each
        # host.
        - name: calico-node
          image: quay.io/calico/node:v3.2.1-2-g66f903c-arm64
          env:
            # The location of the Calico etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # Location of the CA certificate for etcd.
            - name: ETCD_CA_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_ca
            # Location of the client key for etcd.
            - name: ETCD_KEY_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_key
            # Location of the client certificate for etcd.
            - name: ETCD_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_cert
            # Set noderef for node controller.
            - name: CALICO_K8S_NODE_REF
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            # Choose the backend to use.
            - name: CALICO_NETWORKING_BACKEND
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: calico_backend
            # Cluster type to identify the deployment type
            - name: CLUSTER_TYPE
              value: "k8s,bgp"
            # Auto-detect the BGP IP address.
            - name: IP
              value: "autodetect"
            # Enable IPIP
            - name: CALICO_IPV4POOL_IPIP
              value: "Off"
            # Set MTU for tunnel device used if ipip is enabled
            - name: FELIX_IPINIPMTU
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: veth_mtu
            # The default IPv4 pool to create on startup if none exists. Pod IPs will be
            # chosen from this range. Changing this value after installation will have
            # no effect. This should fall within `--cluster-cidr`.
            - name: CALICO_IPV4POOL_CIDR
              value: "192.168.0.0/16"
            # Disable file logging so `kubectl logs` works.
            - name: CALICO_DISABLE_FILE_LOGGING
              value: "true"
            # Set Felix endpoint to host default action to ACCEPT.
            - name: FELIX_DEFAULTENDPOINTTOHOSTACTION
              value: "ACCEPT"
            # Disable IPv6 on Kubernetes.
            - name: FELIX_IPV6SUPPORT
              value: "false"
            # Set Felix logging to "info"
            - name: FELIX_LOGSEVERITYSCREEN
              value: "info"
            - name: FELIX_HEALTHENABLED
              value: "true"
          securityContext:
            privileged: true
          resources:
            requests:
              cpu: 250m
          livenessProbe:
            httpGet:
              path: /liveness
              port: 9099
              host: localhost
            periodSeconds: 10
            initialDelaySeconds: 10
            failureThreshold: 6
          readinessProbe:
            exec:
              command:
              - /bin/calico-node
              - -bird-ready
              - -felix-ready
            periodSeconds: 10
          volumeMounts:
            - mountPath: /lib/modules
              name: lib-modules
              readOnly: true
            - mountPath: /var/run/calico
              name: var-run-calico
              readOnly: false
            - mountPath: /var/lib/calico
              name: var-lib-calico
              readOnly: false
            - mountPath: /calico-secrets
              name: etcd-certs
        # This container installs the Calico CNI binaries
        # and CNI network config file on each node.
        - name: install-cni
          image: quay.io/calico/cni:v3.2.1-2-gf718dd9-arm64
          command: ["/install-cni.sh"]
          env:
            # Name of the CNI config file to create.
            - name: CNI_CONF_NAME
              value: "10-calico.conflist"
            # The location of the Calico etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # The CNI network config to install on each node.
            - name: CNI_NETWORK_CONFIG
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: cni_network_config
            # CNI MTU Config variable
            - name: CNI_MTU
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: veth_mtu
          volumeMounts:
            - mountPath: /host/opt/cni/bin
              name: cni-bin-dir
            - mountPath: /host/etc/cni/net.d
              name: cni-net-dir
            - mountPath: /calico-secrets
              name: etcd-certs
      volumes:
        # Used by calico/node.
        - name: lib-modules
          hostPath:
            path: /lib/modules
        - name: var-run-calico
          hostPath:
            path: /var/run/calico
        - name: var-lib-calico
          hostPath:
            path: /var/lib/calico
        # Used to install CNI.
        - name: cni-bin-dir
          hostPath:
            path: /opt/cni/bin
        - name: cni-net-dir
          hostPath:
            path: /etc/cni/net.d
        # Mount in the etcd TLS secrets with mode 400.
        # See https://kubernetes.io/docs/concepts/configuration/secret/
        - name: etcd-certs
          secret:
            secretName: calico-etcd-secrets
            defaultMode: 0400
---

apiVersion: v1
kind: ServiceAccount
metadata:
  name: calico-node
  namespace: kube-system

---

# This manifest deploys the Calico Kubernetes controllers.
# See https://github.com/projectcalico/kube-controllers
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: calico-kube-controllers
  namespace: kube-system
  labels:
    k8s-app: calico-kube-controllers
  annotations:
    scheduler.alpha.kubernetes.io/critical-pod: ''
spec:
  # The controllers can only have a single active instance.
  replicas: 1
  strategy:
    type: Recreate
  template:
    metadata:
      name: calico-kube-controllers
      namespace: kube-system
      labels:
        k8s-app: calico-kube-controllers
    spec:
      # The controllers must run in the host network namespace so that
      # it isn't governed by policy that would prevent it from working.
      hostNetwork: true
      tolerations:
        # Mark the pod as a critical add-on for rescheduling.
        - key: CriticalAddonsOnly
          operator: Exists
        - key: node-role.kubernetes.io/master
          effect: NoSchedule
      serviceAccountName: calico-kube-controllers
      containers:
        - name: calico-kube-controllers
          image: quay.io/calico/kube-controllers:v3.2.0-6-g2cb0d61-arm64
          env:
            # The location of the Calico etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # Location of the CA certificate for etcd.
            - name: ETCD_CA_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_ca
            # Location of the client key for etcd.
            - name: ETCD_KEY_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_key
            # Location of the client certificate for etcd.
            - name: ETCD_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_cert
            # Choose which controllers to run.
            - name: ENABLED_CONTROLLERS
              value: policy,profile,workloadendpoint,node
          volumeMounts:
            # Mount in the etcd TLS secrets.
            - mountPath: /calico-secrets
              name: etcd-certs
          readinessProbe:
            exec:
              command:
              - /usr/bin/check-status
              - -r
      volumes:
        # Mount in the etcd TLS secrets with mode 400.
        # See https://kubernetes.io/docs/concepts/configuration/secret/
        - name: etcd-certs
          secret:
            secretName: calico-etcd-secrets
            defaultMode: 0400

---

apiVersion: v1
kind: ServiceAccount
metadata:
  name: calico-kube-controllers
  namespace: kube-system
```

## Verify the install
```
watch -n1 kubectl get pods -o wide -n kube-system

Every 1.0s: kubectl get pods -o wide -n kube-system                                                                                                                                                           master1: Mon Aug 27 01:52:07 2018

NAME                                       READY     STATUS    RESTARTS   AGE       IP              NODE
calico-kube-controllers-576c54bd4d-drnj5   1/1       Running   0          2m        172.16.0.133    node2
calico-node-4z52n                          2/2       Running   0          2m        172.16.0.130    master1
calico-node-npzc2                          2/2       Running   0          2m        172.16.0.132    node1
calico-node-q72gt                          2/2       Running   0          2m        172.16.0.134    node3
calico-node-wwbwj                          2/2       Running   0          2m        172.16.0.133    node2
kube-apiserver-master1                     1/1       Running   2          49m       172.16.0.130    master1
kube-controller-manager-master1            1/1       Running   0          48m       172.16.0.130    master1
kube-dns-6448b967fc-z6k9n                  3/3       Running   0          49m       192.168.135.0   node3
kube-proxy-7rt6g                           1/1       Running   0          25m       172.16.0.133    node2
kube-proxy-prrqf                           1/1       Running   0          49m       172.16.0.130    master1
kube-proxy-qpwgg                           1/1       Running   0          25m       172.16.0.132    node1
kube-proxy-z5vqq                           1/1       Running   0          25m       172.16.0.134    node3
kube-scheduler-master1                     1/1       Running   0          49m       172.16.0.130    master1      172.16.0.130   master1

$ kubectl get nodes
NAME      STATUS    ROLES     AGE       VERSION
master1   Ready     master    51m       v1.9.6
node1     Ready     <none>    27m       v1.9.6
node2     Ready     <none>    27m       v1.9.6
node3     Ready     <none>    27m       v1.9.6
```
