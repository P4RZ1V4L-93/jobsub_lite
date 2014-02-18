#!/bin/sh
if [ "$1" = "" ]; then
    echo "usage: $0 server [clusterid] "
    echo "retrieve job (clusterid)'s output back from server"
    exit 0
fi
source ./setup_env.sh
MACH=$1
CLUSTER=$2
if [ "$CLUSTER" = "" ];then
    CLUSTER=1
fi
export SERVER=https://${MACH}:8443

mkdir -p curl
mkdir -p python
#hardcode group for now
GROUP=nova
cd curl
curl -k --cert /tmp/x509up_u${UID} -H "Accept: application/x-download" -o $CLUSTER.zip -X GET $SERVER/jobsub/acctgroups/${GROUP}/jobs/${CLUSTER}/sandbox/
cd -
cd python
../$EXEPATH/jobsub_fetchlog.py --group $GROUP --jobsub-server $SERVER  --job $CLUSTER
cd -