# Born2BeRootTester
Tested for Debian only

Check the mandatory part only of Born2BeRoot

If you specify the monitoring script, the tester will check for the cron tab
configuration, not how it works

Feel free to submit an issue on bugs, subject error or if you have a contructive
critism on how the tester work :)

## HOW TO USE

> on the Born2BeRoot machine

```bash
bash$ git clone git@github.com:Pixailz/Born2BeRootTester
bash$ cd Born2BeRootTester
bash$ sudo ./grade_me.sh -h
Usage : ./grade_me.sh -u LOGIN [-m MONITORING_PATH]
    -h : show this help
	-u : the login of the student
	-m : the path of the monitoring
```
