# TO DO
## Определить, какие нужны опции и реализовать их

1. Опции
splunk diag --exclude "*/passwd"

Files excluded by the --exclude feature are listed in excluded_filelist.txt in the diag bundle to ensure Splunk Support can interpret the diag.


  --collect=<list>      Declare a set of components to gather, as a
                      comma-separated list, overriding any prior choices

  --enable=<component_name>
                      Add a component to the work list

  --disable=<component_name>
                      Remove a component from the work list

2. Компоненты описаны в таблице:
Component	Description	Options
conf_replication_summary	A directory listing of replication summaries produced by search head clustering. This component is not available in Splunk Web.	

3. Redact search strings

4. upload
