#!/bin/bash
for var in clusterFiltering.py Cluster.py combine_analysis.py group2xml.py GroupPlotter.py Group.py json2session_k8s.py parallel_gzip.py Re-arrange_Data.py ssdeep_payloadClean.py TcpPayloadConverter.py XmlConverter.py
do
	bandit $var  >> {$var}_report.txt
done
