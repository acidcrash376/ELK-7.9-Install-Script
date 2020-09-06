# ELK-7.9-Install-Script

[Description]
This is a shell script to automate the install of Elasticsearch, Logstash and Kibana with a nginx reverse proxy onto a debian based system (Tested Ubuntu 20.04) It is purely to get you up and running as I wrote it for my own lab needs and in no way optimised for Production Use.

[Usage]
Due to the need to add new repo's, install packages and configure system services; sudo access is required. 
sudo ./elk_7-9.sh 
That's it, no parameters required. It's to be run locally and will auto-input your hostname and IP into the config's where required. I have not tested it in an environment with multiple interfaces and IP's so if you use it in such an environment I suggest you ammend the variable defined at the beginning. 

[Notes]
This is only the initial version and as such, still work in progress. If you notice any issues or have a suggestion, please let me know and if I think it worth adding then I will try do so.
