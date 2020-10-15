#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import findspark
findspark.init()
from pyspark.sql import Row, SQLContext, SparkSession, window
from pyspark import SparkConf
# Import data types
from pyspark.sql import Window
from pyspark.sql.types import *
import  pyspark.sql.functions as f


# In[ ]:


conf = SparkConf()
conf.setMaster("k8s://https://192.168.50.123:6443")
conf.setAppName("json2parquet_k8s")
conf.set("spark.kubernetes.executor.container.image", "smileocean/spark-py:spark_3.0.0")
conf.set("spark.kubernetes.namespace", "spark")
conf.set("spark.executor.instances", "1")
conf.set("spark.executor.cores", "6")
conf.set("spark.driver.memory", "8g")
conf.set("spark.executor.memory", "16g")
conf.set("spark.kubernetes.pyspark.pythonVersion", "3")
conf.set("spark.kubernetes.authenticate.driver.serviceAccountName", "spark")
conf.set("spark.kubernetes.authenticate.serviceAccountName", "spark")
conf.set("spark.driver.host", "jupyter-notebook-service.spark.svc.cluster.local")
conf.set("spark.driver.port", "29413")
conf.set("spark.hadoop.dfs.replication", "2")
# generate the worker nodes.
spark = SparkSession.builder.config(conf=conf).getOrCreate()


# 
# ## json2parquet
# 

# In[ ]:


json_schema = StructType().add("_source",
                               StructType().add("layers"
                                                , StructType()
                                                .add("country", StringType())
                                                .add("domain", StringType())
                                                .add("isp", StringType())
                                                .add("isInternal", BooleanType())
                                                .add("frame.len", ArrayType(StringType()))
                                                .add("frame.protocols", ArrayType(StringType()))
                                                .add("frame.time_epoch", ArrayType(StringType()))
                                                .add("ip.src", ArrayType(StringType()))
                                                .add("ip.dst", ArrayType(StringType()))
                                                .add("ip.proto", ArrayType(StringType()))
                                                .add("tcp.srcport", ArrayType(StringType()))
                                                .add("tcp.dstport", ArrayType(StringType()))
                                                .add("tcp.hdr_len", ArrayType(StringType()))
                                                .add("tcp.len", ArrayType(StringType()))
                                                .add("tcp.payload", ArrayType(StringType()))
                                                .add("udp.srcport", ArrayType(StringType()))
                                                .add("udp.dstport", ArrayType(StringType()))
                                                .add("udp.length", ArrayType(StringType()))
                                                .add("icmp.length", ArrayType(StringType()))
                                                .add("icmp.length.original_datagram", ArrayType(StringType()))
                                               ))


# In[ ]:


# multipleline
isp = "中華電信"
date = "2020_01_10"
date2 = "".join(date.split("_"))
pcapPath = "hdfs://192.168.50.200/user/hdfs/pcap_json/" + date + "/" + isp + "/"
pcap_df_multiline = spark.read.schema(json_schema).option("multiline", "true").json(pcapPath)
pcap_df = pcap_df_multiline.select("_source.layers.*")


# In[ ]:


packet_df = pcap_df.select(
                    f.col("domain")
                    , f.col("country")
                    , f.col("isp")
                    , f.col("isInternal").alias("isOutbound")
                    , f.col("`tcp.len`").getItem(0).alias("tcp_len").cast(IntegerType())
                    , f.col("`tcp.hdr_len`").getItem(0).alias("tcp_hdr_len").cast(IntegerType())
                    , f.col("`tcp.payload`").alias("tcp_payload").cast(ArrayType(StringType()))
                    , f.col("`frame.protocols`").getItem(0).alias("frame_protocols")
                    , f.col("`frame.len`").getItem(0).alias("frame_len").cast(IntegerType())
                    , f.col("`ip.src`").getItem(0).alias("ip_src")
                    , f.col("`ip.dst`").getItem(0).alias("ip_dst")
                    , f.col("`tcp.srcport`").getItem(0).alias("tcp_srcport").cast(IntegerType())
                    , f.col("`tcp.dstport`").getItem(0).alias("tcp_dstport").cast(IntegerType())
                    , f.col("`udp.length`").getItem(0).alias("udp_length").cast(IntegerType())
                    , f.col("`udp.srcport`").getItem(0).alias("udp_srcport").cast(IntegerType())
                    , f.col("`udp.dstport`").getItem(0).alias("udp_dstport").cast(IntegerType())
                    , f.col("`icmp.length`").getItem(0).alias("icmp_length").cast(IntegerType())
                    , f.col("`icmp.length.original_datagram`").getItem(0).alias("icmp_length_original_datagram").cast(IntegerType())
                    , f.col("`ip.proto`").getItem(0).alias("ip_proto")
                    , f.col("`frame.time_epoch`").getItem(0).alias("frame_time_epoch").cast(DoubleType()))#.orderBy("`frame.time_epoch`")


# In[ ]:


def maxip(ip1, ip2):
    arr = ip1.split(".")
    arr2 = ip2.split(".")
    iplong = (int(arr[0]) << 24) + (int(arr[1]) << 16) + (int(arr[2]) << 8) + int(arr[3])
    iplong2 = (int(arr2[0]) << 24) + (int(arr2[1]) << 16) + (int(arr2[2]) << 8) + int(arr2[3])
    if iplong > iplong2:
        return ip1
    else:
        return ip2

def minip(ip1, ip2):
    arr = ip1.split(".")
    arr2 = ip2.split(".")
    iplong = (int(arr[0]) << 24) + (int(arr[1]) << 16) + (int(arr[2]) << 8) + int(arr[3])
    iplong2 = (int(arr2[0]) << 24) + (int(arr2[1]) << 16) + (int(arr2[2]) << 8) + int(arr2[3])
    if iplong > iplong2:
        return ip2
    else:
        return ip1


# In[ ]:


udf_minip = f.udf(minip, StringType())
udf_maxip = f.udf(maxip, StringType())
result = packet_df.withColumn("min_ip", udf_minip('ip_src', 'ip_dst'))
result = result.withColumn("max_ip", udf_maxip('ip_src', 'ip_dst'))
result = result.withColumn("min_port"
            , f.when(f.col('tcp_srcport').isNotNull()
            , f.least('tcp_srcport', "tcp_dstport")).otherwise(f.least('udp_srcport', "udp_dstport")))
result = result.withColumn("max_port"
            , f.when(f.col('tcp_srcport').isNotNull()
            , f.greatest('tcp_srcport', "tcp_dstport")).otherwise(f.greatest('udp_srcport', "udp_dstport")))


# In[ ]:


def longestCommonPrefix(strs):
    if not strs: return None
    s1 = min(strs)
    s2 = max(strs)
    for i, c in enumerate(s1):
        if c != s2[i]:
            return s1[:i]
    return s1

udf_common_frame_protocols = f.udf(longestCommonPrefix, StringType())

def detailedProtocol(strs):
    if not strs: return None
    maxidx = 0
    for i in range(len(strs)-1):
        if len(strs[i+1]) > len(strs[maxidx]):
            maxidx = i+1
    return strs[maxidx]

udf_detailedProto = f.udf(detailedProtocol, StringType())

def timeDelta(t_last, t_first):
    delta = t_last - t_first
    return delta

udf_timeDelta = f.udf(timeDelta, FloatType())


# In[ ]:


w = Window.partitionBy("min_ip", "max_ip", "min_port", "max_port", "ip_proto").orderBy("frame_time_epoch")
result = result.withColumn("prev_time", f.lag("frame_time_epoch",1).over(w))

result = result.withColumn("delta", result["frame_time_epoch"] - result["prev_time"])
result = result.withColumn("isChange", f.when(result["delta"] > 120, 1).otherwise(0))
result = result.withColumn("group_id", f.sum("isChange").over(w))

result = result.groupBy("min_ip", "max_ip", "min_port", "max_port","ip_proto","group_id").agg(
                                          f.sum("frame_len").alias("session_tt_frame_length"), 
                                          f.sum(f.when(f.col("isOutbound")==False
                                                       , f.col("frame_len"))).alias("session_i_tt_frame_length"),
                                          f.sum(f.when(f.col("isOutbound")==True
                                                       , f.col("frame_len"))).alias("session_o_tt_frame_length"),
#                                           f.first("`frame.number`").alias("frame.number"),
                                          f.count("ip_src").alias("session_tt_packet"),
                                          f.count(f.when(f.col("isOutbound")==False
                                                         , f.col("ip_src"))).alias("session_i_tt_packet"),
                                          f.count(f.when(f.col("isOutbound")==True
                                                         , f.col("ip_src"))).alias("session_o_tt_packet"),
                                          udf_timeDelta(f.max("frame_time_epoch"),f.min("frame_time_epoch")).alias("session_duration"),
#                                           f.first("`frame.time`").alias("frame.time"),
                                          f.sum("udp_length").alias("udp_tt_length"),
                                          f.sum(f.when(f.col("isOutbound")==False
                                                       , f.col("udp_length"))).alias("udp_i_tt_length"),
                                          f.sum(f.when(f.col("isOutbound")==True
                                                       , f.col("udp_length"))).alias("udp_o_tt_length"),
                                          f.avg(f.when(f.col("isOutbound")==False
                                                       , f.col("udp_length"))).alias("udp_i_avg_length"),
                                          f.avg(f.when(f.col("isOutbound")==True
                                                       , f.col("udp_length"))).alias("udp_o_avg_length"),
                                          f.sum("icmp_length").alias("icmp_tt_length"),
                                          f.sum(f.when(f.col("isOutbound")==False
                                                       , f.col("icmp_length"))).alias("icmp_i_tt_length"),
                                          f.sum(f.when(f.col("isOutbound")==True
                                                       , f.col("icmp_length"))).alias("icmp_o_tt_length"),
                                          f.avg(f.when(f.col("isOutbound")==False
                                                       , f.col("icmp_length"))).alias("icmp_i_avg_length"),
                                          f.avg(f.when(f.col("isOutbound")==True
                                                       , f.col("icmp_length"))).alias("icmp_o_avg_length"),
                                          f.sum("icmp_length_original_datagram").alias("icmp_tt_original_datagram_length"),
                                          f.sum(f.when(f.col("isOutbound")==False
                                                       , f.col("icmp_length_original_datagram"))).alias("icmp_i_tt_datagram_length"),
                                          f.sum(f.when(f.col("isOutbound")==True
                                                       , f.col("icmp_length_original_datagram"))).alias("icmp_o_tt_datagram_length"),
                                          f.avg(f.when(f.col("isOutbound")==False
                                                       , f.col("icmp_length_original_datagram"))).alias("icmp_i_avg_datagram_length"),
                                          f.avg(f.when(f.col("isOutbound")==True
                                                       , f.col("icmp_length_original_datagram"))).alias("icmp_o_avg_datagram_length"),
                                          f.sum("tcp_hdr_len").alias("tcp_hdr_len_sum"),
                                          f.sum("tcp_len").alias("tcp_tt_payload_length"),
                                          f.sum(f.when(f.col("isOutbound")==False
                                                       , f.col("tcp_len"))).alias("tcp_i_tt_payload_length"),
                                          f.sum(f.when(f.col("isOutbound")==True
                                                       , f.col("tcp_len"))).alias("tcp_o_tt_payload_length"),
                                          f.avg(f.when(f.col("isOutbound")==False
                                                       , f.col("tcp_len"))).alias("tcp_i_avg_payload_length"),
                                          f.avg(f.when(f.col("isOutbound")==True
                                                       , f.col("tcp_len"))).alias("tcp_o_avg_payload_length"),
                                          f.collect_list("frame_time_epoch").alias("session_time_list"),
                                          f.collect_list(f.when(f.col("isOutbound")==False, f.col("tcp_payload"))).alias("tcp_i_payload_list"),
                                          f.collect_list(f.when(f.col("isOutbound")==True, f.col("tcp_payload"))).alias("tcp_o_payload_list"),
#                                           f.max(f.col("tcp_i_payload_list")).alias("tcp_i_payload_list_max"),
#                                           f.max(f.col("tcp_o_payload_list")).alias("tcp_o_payload_list_max"),
                                          f.min("frame_time_epoch").alias("session_time"),
                                          udf_common_frame_protocols(f.collect_list(f.when(f.col("isOutbound")==False
                                                                                           , f.col("frame_protocols")))).alias("frame_i_common_protocols"),
                                          udf_common_frame_protocols(f.collect_list(f.when(f.col("isOutbound")==True
                                                                                           , f.col("frame_protocols")))).alias("frame_o_common_protocols"),
                                          udf_detailedProto(f.collect_list(f.when(f.col("isOutbound")==False
                                                                                           , f.col("frame_protocols")))).alias("frame_i_max_protocols"),
                                          udf_detailedProto(f.collect_list(f.when(f.col("isOutbound")==True
                                                                                           , f.col("frame_protocols")))).alias("frame_o_max_protocols"),
                                          f.first(f.when(f.col("isOutbound")==False, f.col("ip_src")).otherwise(f.col("ip_dst"))).alias("ip_src"),
                                          f.first(f.when(f.col("isOutbound")==False, f.col("ip_dst")).otherwise(f.col("ip_src"))).alias("ip_dst"),
                                          f.first(f.when(f.col("isOutbound")==False, f.col("tcp_srcport")).otherwise(f.col("tcp_dstport"))).alias("tcp_srcport"),
                                          f.first(f.when(f.col("isOutbound")==False, f.col("tcp_dstport")).otherwise(f.col("tcp_srcport"))).alias("tcp_dstport"),
                                          f.first(f.when(f.col("isOutbound")==False, f.col("udp_srcport")).otherwise(f.col("udp_dstport"))).alias("udp_srcport"),
                                          f.first(f.when(f.col("isOutbound")==False, f.col("udp_dstport")).otherwise(f.col("udp_srcport"))).alias("udp_dstport"),
                                          f.first("domain").alias("domain"),
                                          f.first("country").alias("country"),
                                          f.first("isp").alias("isp")
                                        )


# In[ ]:


# # of packets
result = result.withColumn("session_tt_packet",f.col("session_tt_packet").cast(IntegerType()))
result = result.withColumn("session_i_tt_packet",f.col("session_i_tt_packet").cast(IntegerType()))
result = result.withColumn("session_o_tt_packet",f.col("session_o_tt_packet").cast(IntegerType()))

# tcp 
result = result.withColumn("tcp_tt_payload_length",f.col("tcp_tt_payload_length").cast(IntegerType()))
result = result.withColumn("tcp_i_tt_payload_length",f.col("tcp_i_tt_payload_length").cast(IntegerType()))
result = result.withColumn("tcp_o_tt_payload_length",f.col("tcp_o_tt_payload_length").cast(IntegerType()))

# udp
result = result.withColumn("udp_tt_length",f.col("udp_tt_length").cast(IntegerType()))
result = result.withColumn("udp_i_tt_length",f.col("udp_i_tt_length").cast(IntegerType()))
result = result.withColumn("udp_o_tt_length",f.col("udp_o_tt_length").cast(IntegerType()))

# icmp
result = result.withColumn("icmp_tt_length",f.col("icmp_tt_length").cast(IntegerType()))
result = result.withColumn("icmp_i_tt_length",f.col("icmp_i_tt_length").cast(IntegerType()))
result = result.withColumn("icmp_o_tt_length",f.col("icmp_o_tt_length").cast(IntegerType()))
result = result.withColumn("icmp_tt_original_datagram_length",f.col("icmp_tt_original_datagram_length").cast(IntegerType()))
result = result.withColumn("icmp_i_tt_datagram_length",f.col("icmp_i_tt_datagram_length").cast(IntegerType()))
result = result.withColumn("icmp_o_tt_datagram_length",f.col("icmp_o_tt_datagram_length").cast(IntegerType()))


# In[ ]:


result = result.select("session_time", "session_time_list", "session_duration", 
                       "session_tt_packet","session_i_tt_packet", "session_o_tt_packet",
                       "session_tt_frame_length", "session_i_tt_frame_length", "session_o_tt_frame_length",
                       "udp_tt_length", "udp_i_tt_length", "udp_o_tt_length", "udp_i_avg_length","udp_o_avg_length",
                       "icmp_tt_length", "icmp_i_tt_length", "icmp_o_tt_length","icmp_i_avg_length", "icmp_o_avg_length",
                       "icmp_tt_original_datagram_length", "icmp_i_tt_datagram_length", "icmp_o_tt_datagram_length",
                       "icmp_i_avg_datagram_length", "icmp_o_avg_datagram_length",
                       "tcp_hdr_len_sum", "tcp_tt_payload_length", "tcp_i_tt_payload_length", "tcp_o_tt_payload_length",
                       "tcp_i_avg_payload_length", "tcp_o_avg_payload_length",
                       "ip_src", "ip_dst", "ip_proto", 
                       "tcp_srcport", "tcp_dstport", "udp_srcport", "udp_dstport",
                       "country", "domain", "isp",
                       "frame_i_common_protocols", "frame_o_common_protocols",
                       "frame_i_max_protocols", "frame_o_max_protocols",
                       "tcp_i_payload_list", "tcp_o_payload_list"
                      )


# In[ ]:


# session-based parquet file
result.write.parquet("hdfs://192.168.50.200/user/hdfs/parquet/"+ date + "/" + isp + "/session_parquet/" + date2 + "_session.parquet")

