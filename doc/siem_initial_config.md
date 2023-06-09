A couple of examples of SIEM Splunk queries:

- Splunk query to detect a potential ICMP flood:  
```sourcetype="stream:icmp" type_string="Echo"```  
```   | bin _time span=10s```  
```   | stats count AS Echo_Requests BY _time, src_ip, dest_ip```  
```   | where Echo_Requests > 40```  
```   | rename src_ip AS "Attacker (src_ip)", dest_ip AS "Victim (dest_ip)"```  

- Splunk query to detect a potential TCP SYN flood:  
```sourcetype="stream:tcp" type_string="SYN"```  
```   | bin _time span=5s```  
```   | stats count AS Echo_Requests BY _time, src_ip, dest_ip```  
```   | where Echo_Requests > 100```  
```   | rename src_ip AS "Attacker (src_ip)", dest_ip AS "Victim (dest_ip)"```  

- Splunk query to detect a potential UDP flood:  
```sourcetype="stream:UDP"```  
```   | bin _time span=5s```  
```   | stats count AS Echo_Requests BY _time, src_ip, dest_ip```  
```   | where Echo_Requests > 60```  
```   | rename src_ip AS "Attacker (src_ip)", dest_ip AS "Victim (dest_ip)"```  

- Splunk query to LOG an ICMP Flood ~ Smart Prediction  
```sourcetype="stream:icmp"```  
```| bin _time span=5s```  
```| stats count AS filtered_events BY _time, dest_ip, src_ip```  
```| eval attack = if(filtered_events > 150, "Yes", "No")```  
```| table src_ip, dest_ip, _time, filtered_events, attack```  
