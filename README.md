# Raspberry Pi3, Kubernetes 1.12.2, Calico 3.3.0

This guide is to help you deploy Kubernetes and Calico on Raspberry Pi3's. This guide is based on 5 pi's (1 master, 1 etcd, 3 worker nodes). I had challenges with the kube-apiserver crashing during the `kubeadm init` bring up so I have dedicated one pi to run etcd for both Kubernetes and Calico.

## On mac
Install pv and awscli for hypriot flash util. Install wget to grab hypriot arm64 build. Flash sdcard for master1
```
brew install pv
brew install awscli
brew install wget
wget https://github.com/DieterReuter/-builder-rpi64/releases/download/v20180429-184538/hypriotos-rpi64-v20180429-184538.img.zip
curl -LO https://github.com/hypriot/flash/releases/download/2.1.1/flash\nchmod +x flash
sudo mv flash /usr/local/bin/flash
flash --hostname master1 hypriotos-rpi64-v20180429-184538.img.zip
```

## Setup master OS
Set up static IP, turn swap off, edit boot config to add cgroup_enable=memory, install utils to ping .local
```
ssh pirate@master1.local
sudo su -
```
vi /etc/network/interfaces.d/eth0
```
allow-hotplug eth0
#iface eth0 inet dhcp
iface eth0 inet static
address 172.16.0.130
gateway 172.16.0.1
#google dns servers
domain_name_servers=8.8.8.8, 8.8.4.4
```
vi /boot/cmdline.txt
```
dwc_otg.lpm_enable=0 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 cgroup_enable=cpuset cgroup_enable=memory cgroup_memory=1 swapaccount=1 elevator=deadline fsck.repair=yes rootwait console=ttyAMA0,115200 net.ifnames=0
```
```
swapoff -a
reboot
ssh pirate@master1.local
sudo su -
apt-get update
apt-get -y install libnss-mdns avahi-utils
```

## Setup etcd
Flash OS for etcd
```
flash --hostname etcd1 hypriotos-rpi64-v20180429-184538.img.zip
```
Set up static IP, turn swap off, edit boot config to add cgroup_enable=memory, install utils to ping .local
```
ssh pirate@etcd1.local
sudo su -
```
vi /etc/network/interfaces.d/eth0
```
allow-hotplug eth0
#iface eth0 inet dhcp
iface eth0 inet static
address 172.16.0.131
gateway 172.16.0.1
#google dns servers
domain_name_servers=8.8.8.8, 8.8.4.4
```
vi /boot/cmdline.txt
```
dwc_otg.lpm_enable=0 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 cgroup_enable=cpuset cgroup_enable=memory cgroup_memory=1 swapaccount=1 elevator=deadline fsck.repair=yes rootwait console=ttyAMA0,115200 net.ifnames=0
```
```
swapoff -a
reboot
ssh pirate@etcd1.local
sudo su -
apt-get update
apt-get -y install libnss-mdns avahi-utils
```
Set up user for etcd
```
mkdir -p /var/lib/etcd
groupadd -f -g 1501 etcd
useradd -c "Etcd key-value store user" -d /var/lib/etcd -s /bin/false -g etcd -u 1501 etcd
chown -R etcd:etcd /var/lib/etcd
```
Download and put etcd binaries in /usr/local/bin
```
curl -ksL 'https://github.com/coreos/etcd/releases/download/v3.2.24/etcd-v3.2.24-linux-arm64.tar.gz' | tar -xzvf -
cp etcd-v3.2.24-linux-arm64/etcd* /usr/local/bin
```
vi /etc/systemd/system/etcd.service
```
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
```
Enable and start etcd systemd service
```
systemctl daemon-reload
systemctl enable etcd
systemctl start etcd.service
systemctl status -l etcd.service
```
## Install kubeadm on master1
Install kubeadm packages and generate a token.
```
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list
apt-get update && apt-get install -y kubelet=1.12.2-00 kubeadm=1.12.2-00 kubernetes-cni=0.6.0-00 kubectl=1.12.2-00
kubeadm token generate
```
Save the token output and will add to the config.yaml file.
```
vl7c34.anxkiafldl3g4hb4
```
vi config-alpha2.yaml
```
api:
  advertiseAddress: 172.16.0.130
  bindPort: 6443
  controlPlaneEndpoint: ""
apiServerCertSANs:
- 172.16.0.130
- 127.0.0.1
apiVersion: kubeadm.k8s.io/v1alpha2
auditPolicy:
  logDir: /var/log/kubernetes/audit
  logMaxAge: 2
  path: ""
bootstrapTokens:
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  token: vl7c34.anxkiafldl3g4hb4
  ttl: 0s
  usages:
  - signing
  - authentication
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
etcd:
  external:
    caFile: ""
    certFile: ""
    endpoints:
    - http://172.16.0.131:2379
    keyFile: ""
imageRepository: k8s.gcr.io
kind: MasterConfiguration
kubeProxy:
  config:
    bindAddress: 0.0.0.0
    clientConnection:
      acceptContentTypes: ""
      burst: 10
      contentType: application/vnd.kubernetes.protobuf
      kubeconfig: /var/lib/kube-proxy/kubeconfig.conf
      qps: 5
    clusterCIDR: 192.168.0.0/16
    configSyncPeriod: 15m0s
    conntrack:
      max: null
      maxPerCore: 32768
      min: 131072
      tcpCloseWaitTimeout: 1h0m0s
      tcpEstablishedTimeout: 24h0m0s
    enableProfiling: false
    healthzBindAddress: 0.0.0.0:10256
    hostnameOverride: ""
    iptables:
      masqueradeAll: false
      masqueradeBit: 14
      minSyncPeriod: 0s
      syncPeriod: 30s
    ipvs:
      excludeCIDRs: null
      minSyncPeriod: 0s
      scheduler: ""
      syncPeriod: 30s
    metricsBindAddress: 127.0.0.1:10249
    mode: ""
    nodePortAddresses: null
    oomScoreAdj: -999
    portRange: ""
    resourceContainer: /kube-proxy
    udpIdleTimeout: 250ms
kubeletConfiguration:
  baseConfig:
    address: 0.0.0.0
    authentication:
      anonymous:
        enabled: false
      webhook:
        cacheTTL: 2m0s
        enabled: true
      x509:
        clientCAFile: /etc/kubernetes/pki/ca.crt
    authorization:
      mode: Webhook
      webhook:
        cacheAuthorizedTTL: 5m0s
        cacheUnauthorizedTTL: 30s
    cgroupDriver: cgroupfs
    cgroupsPerQOS: true
    clusterDNS:
    - 10.96.0.10
    clusterDomain: cluster.local
    containerLogMaxFiles: 5
    containerLogMaxSize: 10Mi
    contentType: application/vnd.kubernetes.protobuf
    cpuCFSQuota: true
    cpuManagerPolicy: none
    cpuManagerReconcilePeriod: 10s
    enableControllerAttachDetach: true
    enableDebuggingHandlers: true
    enforceNodeAllocatable:
    - pods
    eventBurst: 10
    eventRecordQPS: 5
    evictionHard:
      imagefs.available: 15%
      memory.available: 100Mi
      nodefs.available: 10%
      nodefs.inodesFree: 5%
    evictionPressureTransitionPeriod: 5m0s
    failSwapOn: true
    fileCheckFrequency: 20s
    hairpinMode: promiscuous-bridge
    healthzBindAddress: 127.0.0.1
    healthzPort: 10248
    httpCheckFrequency: 20s
    imageGCHighThresholdPercent: 85
    imageGCLowThresholdPercent: 80
    imageMinimumGCAge: 2m0s
    iptablesDropBit: 15
    iptablesMasqueradeBit: 14
    kubeAPIBurst: 10
    kubeAPIQPS: 5
    makeIPTablesUtilChains: true
    maxOpenFiles: 1000000
    maxPods: 110
    nodeStatusUpdateFrequency: 10s
    oomScoreAdj: -999
    podPidsLimit: -1
    port: 10250
    registryBurst: 10
    registryPullQPS: 5
    resolvConf: /etc/resolv.conf
    rotateCertificates: true
    runtimeRequestTimeout: 2m0s
    serializeImagePulls: true
    staticPodPath: /etc/kubernetes/manifests
    streamingConnectionIdleTimeout: 4h0m0s
    syncFrequency: 1m0s
    volumeStatsAggPeriod: 1m0s
kubernetesVersion: v1.12.2
networking:
  dnsDomain: cluster.local
  podSubnet: 192.168.0.0/16
  serviceSubnet: 10.96.0.0/12
nodeRegistration:
  criSocket: /var/run/dockershim.sock
  name: master1
  taints:
  - effect: NoSchedule
    key: node-role.kubernetes.io/master
unifiedControlPlaneImage: ""
```
Prepull control plane images
```
kubeadm config images pull
```
Open a second terminal session to master1. We need to run a job to increase the kube-apiserver delay so it can can complete during the kubeadm init.
```
ssh pirate@master1.local
sudo su -
watch -n 1.0 "sed -i 's/initialDelaySeconds: [0-9]\+/initialDelaySeconds: 180/' /etc/kubernetes/manifests/kube-apiserver.yaml"
```
Back on the first session Initialize the cluster
```
kubeadm init --config=config-alpha2.yaml
```
Save the output from the initialization to join worker nodes
```
kubeadm join 172.16.0.130:6443 --token vl7c34.anxkiafldl3g4hb4 --discovery-token-ca-cert-hash sha256:097c5d6832e940e33ca6ee5d3777b794c820035d9b3d0109a5302dccd2cf982c
```
Setup pirate user account to manage kubernetes
```
exit
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```
Validate kubernetes is up. coredns pods will be in pending until we get Calico running.
```
$ kubectl get pods --all-namespaces
NAMESPACE     NAME                              READY   STATUS    RESTARTS   AGE
kube-system   coredns-576cbf47c7-nhc8n          0/1     Pending   0          4m20s
kube-system   coredns-576cbf47c7-pwclr          0/1     Pending   0          4m20s
kube-system   kube-apiserver-master1            1/1     Running   0          4m42s
kube-system   kube-controller-manager-master1   1/1     Running   0          3m30s
kube-system   kube-proxy-7krlr                  1/1     Running   0          4m20s
kube-system   kube-scheduler-master1            1/1     Running   0          4m5s
```

## Setup node1
Flash OS for node1
```
flash --hostname node1 hypriotos-rpi64-v20180429-184538.img.zip
```
Set up static IP, turn swap off, edit boot config to add cgroup_enable=memory, install utils to ping .local
```
ssh pirate@node1.local
sudo su -
```
vi /etc/network/interfaces.d/eth0
```
allow-hotplug eth0
#iface eth0 inet dhcp
iface eth0 inet static
address 172.16.0.132
gateway 172.16.0.1
#google dns servers
domain_name_servers=8.8.8.8, 8.8.4.4
```
vi /boot/cmdline.txt
```
dwc_otg.lpm_enable=0 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 cgroup_enable=cpuset cgroup_enable=memory cgroup_memory=1 swapaccount=1 elevator=deadline fsck.repair=yes rootwait console=ttyAMA0,115200 net.ifnames=0
```
```
swapoff -a
reboot
ssh pirate@node1.local
sudo su -
apt-get update
apt-get -y install libnss-mdns avahi-utils
```
Install kubeadm packages and join cluster
```
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list
apt-get update && apt-get install -y kubelet=1.12.2-00 kubeadm=1.12.2-00 kubernetes-cni=0.6.0-00 kubectl=1.12.2-00
kubeadm join 172.16.0.130:6443 --token vl7c34.anxkiafldl3g4hb4 --discovery-token-ca-cert-hash sha256:097c5d6832e940e33ca6ee5d3777b794c820035d9b3d0109a5302dccd2cf982c
```

## Setup node2
Flash OS for node2
```
flash --hostname node2 hypriotos-rpi64-v20180429-184538.img.zip
```
Set up static IP, turn swap off, edit boot config to add cgroup_enable=memory, install utils to ping .local
```
ssh pirate@node2.local
sudo su -
```
vi /etc/network/interfaces.d/eth0
```
allow-hotplug eth0
#iface eth0 inet dhcp
iface eth0 inet static
address 172.16.0.133
gateway 172.16.0.1
#google dns servers
domain_name_servers=8.8.8.8, 8.8.4.4
```
vi /boot/cmdline.txt
```
dwc_otg.lpm_enable=0 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 cgroup_enable=cpuset cgroup_enable=memory cgroup_memory=1 swapaccount=1 elevator=deadline fsck.repair=yes rootwait console=ttyAMA0,115200 net.ifnames=0
```
```
swapoff -a
reboot
ssh pirate@node2.local
sudo su -
apt-get update
apt-get -y install libnss-mdns avahi-utils
```
Install kubeadm packages and join cluster
```
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list
apt-get update && apt-get install -y kubelet=1.12.2-00 kubeadm=1.12.2-00 kubernetes-cni=0.6.0-00 kubectl=1.12.2-00
kubeadm join 172.16.0.130:6443 --token vl7c34.anxkiafldl3g4hb4 --discovery-token-ca-cert-hash sha256:097c5d6832e940e33ca6ee5d3777b794c820035d9b3d0109a5302dccd2cf982c
```

## Setup node3
Flash OS for node3
```
flash --hostname node3 hypriotos-rpi64-v20180429-184538.img.zip
```
Set up static IP, turn swap off, edit boot config to add cgroup_enable=memory, install utils to ping .local
```
ssh pirate@node3.local
sudo su -
```
vi /etc/network/interfaces.d/eth0
```
allow-hotplug eth0
#iface eth0 inet dhcp
iface eth0 inet static
address 172.16.0.134
gateway 172.16.0.1
#google dns servers
domain_name_servers=8.8.8.8, 8.8.4.4
```
vi /boot/cmdline.txt
```
dwc_otg.lpm_enable=0 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 cgroup_enable=cpuset cgroup_enable=memory cgroup_memory=1 swapaccount=1 elevator=deadline fsck.repair=yes rootwait console=ttyAMA0,115200 net.ifnames=0
```
```
swapoff -a
reboot
ssh pirate@node3.local
sudo su -
apt-get update
apt-get -y install libnss-mdns avahi-utils
```
Install kubeadm packages and join cluster
```
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list
apt-get update && apt-get install -y kubelet=1.12.2-00 kubeadm=1.12.2-00 kubernetes-cni=0.6.0-00 kubectl=1.12.2-00
kubeadm join 172.16.0.130:6443 --token vl7c34.anxkiafldl3g4hb4 --discovery-token-ca-cert-hash sha256:097c5d6832e940e33ca6ee5d3777b794c820035d9b3d0109a5302dccd2cf982c
```
Back on the master validate all nodes are joined to the cluster and in NotReady state
```
$ kubectl get nodes -o wide
NAME      STATUS     ROLES    AGE     VERSION   INTERNAL-IP    EXTERNAL-IP   OS-IMAGE                       KERNEL-VERSION         CONTAINER-RUNTIME
master1   NotReady   master   38m     v1.12.2   172.16.0.130   <none>        Debian GNU/Linux 9 (stretch)   4.14.37-hypriotos-v8   docker://18.4.0
node1     NotReady   <none>   15m     v1.12.2   172.16.0.132   <none>        Debian GNU/Linux 9 (stretch)   4.14.37-hypriotos-v8   docker://18.4.0
node2     NotReady   <none>   5m11s   v1.12.2   172.16.0.133   <none>        Debian GNU/Linux 9 (stretch)   4.14.37-hypriotos-v8   docker://18.4.0
node3     NotReady   <none>   11s     v1.12.2   172.16.0.134   <none>        Debian GNU/Linux 9 (stretch)   4.14.37-hypriotos-v8   docker://18.4.0
```

## Install Calico
### Setup RBAC
```
kubectl apply -f https://docs.projectcalico.org/v3.3/getting-started/kubernetes/installation/rbac.yaml
```
### Modify calico.yaml
In the calico.yaml we need to update `etcd_endpoints:` for our etcd IP, `image:` for (node,cni,kube-controllers) to pull arm64 versions, and disable IPIP (CALICO_IPV4POOL_IPIP).

vi calico.yaml
```
# Calico Version v3.3.0
# https://docs.projectcalico.org/v3.3/releases#v3.3.0
# This manifest includes the following component versions:
#   calico/node:v3.3.0
#   calico/cni:v3.3.0
#   calico/kube-controllers:v3.3.0

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
      nodeSelector:
        beta.kubernetes.io/os: linux
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
          image: quay.io/calico/node:v3.3.0-arm64
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
            - mountPath: /run/xtables.lock
              name: xtables-lock
              readOnly: false
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
          image: quay.io/calico/cni:v3.3.0-arm64
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
        - name: xtables-lock
          hostPath:
            path: /run/xtables.lock
            type: FileOrCreate
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
      nodeSelector:
        beta.kubernetes.io/os: linux
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
          image: quay.io/calico/kube-controllers:v3.3.0-arm64
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
              value: policy,namespace,serviceaccount,workloadendpoint,node
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
### Apply calico.yaml
```
kubectl apply -f calico.yaml
```

## Verify the install
```
watch -n1 kubectl get pods -o wide -n kube-system

Every 1.0s: kubectl get pods -o wide -n kube-system                                                                       master1: Fri Nov  2 08:56:45 2018

NAME                                       READY   STATUS    RESTARTS   AGE     IP                NODE      NOMINATED NODE
calico-kube-controllers-6b7df65c85-4dtmf   1/1     Running   0          2m15s   172.16.0.132      node1     <none>
calico-node-8zlrk                          2/2     Running   0          2m15s   172.16.0.133      node2     <none>
calico-node-ds2tb                          2/2     Running   0          2m15s   172.16.0.134      node3     <none>
calico-node-k9n4c                          2/2     Running   0          2m15s   172.16.0.130      master1   <none>
calico-node-vgcxf                          2/2     Running   0          2m15s   172.16.0.132      node1     <none>
coredns-576cbf47c7-nhc8n                   1/1     Running   0          49m     192.168.166.129   node1     <none>
coredns-576cbf47c7-pwclr                   1/1     Running   0          49m     192.168.166.128   node1     <none>
kube-apiserver-master1                     1/1     Running   0          34s     172.16.0.130      master1   <none>
kube-controller-manager-master1            1/1     Running   0          30s     172.16.0.130      master1   <none>
kube-proxy-7krlr                           1/1     Running   0          49m     172.16.0.130      master1   <none>
kube-proxy-bcp8j                           1/1     Running   0          11m     172.16.0.134      node3     <none>
kube-proxy-bfh85                           1/1     Running   0          16m     172.16.0.133      node2     <none>
kube-proxy-qtcfv                           1/1     Running   0          26m     172.16.0.132      node1     <none>
kube-scheduler-master1                     1/1     Running   0          34s     172.16.0.130      master1   <none>

$ kubectl get nodes
NAME      STATUS   ROLES    AGE   VERSION
master1   Ready    master   50m   v1.12.2
node1     Ready    <none>   26m   v1.12.2
node2     Ready    <none>   16m   v1.12.2
node3     Ready    <none>   11m   v1.12.2
```
Reference URLs
```
https://github.com/kubernetes/kubernetes/issues/61277
https://www.kevinhooke.com/2016/07/12/configuring-a-static-ip-on-hypriotos-for-the-raspberry-pi/
https://icicimov.github.io/blog/kubernetes/Kubernetes-cluster-step-by-step-Part3/
https://github.com/kubernetes/kubeadm/issues/413
```
