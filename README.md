[![N|Solid](https://paraqum.com/assets/icons/common/pq_white.png)](https://paraqum.com/)
# pq_pcap_packet_reader
[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

ParaQum Pcap library based packet sniffing module

#### Repository
http://192.168.1.100/chandulanethmal/pq_pcap_packet_reader.git

#### Project Task URL


#### Main Branches 
| Branch | Description |
| ------ | ------ |
| master    | Latest stable branch :lock: | 

#### Feature Branches 
| Branch | Feature | Communication Channel |
| ------ | ------ | ------ |

#### Development Branches 
| Branch | Description | Assigned To |
| ------ | ------ | ------ |
| master | initial version| chandula |
\

#### Tags
| Tag | Description |
| ------ | ------ |

#### Todos
Features to complete for this phase.

[x] Bidirectional acceleration

[x] Sessino Analysis

[] Connect to node side

#### Setup
##### Prerequisites
###### Git Dependencies
* :no_entry_sign:

###### Ubuntu
* NodeJs - v12 or higher (Recommended)

```sh
$ sudo apt-get update
$ sudo apt-get install nodejs
```

* NPM - Latest (Recommended)

```sh
$ sudo apt-get install npm
```
* Zero-MQ library

* Git - :smiley:

###### Windows
:disappointed: - ``` Not Defined ```

###### Mac
:disappointed: - ``` Not Defined ```

#### Installation

```sh
$ git clone -b <Branch Assigned> http://192.168.1.100/chandulanethmal/pq_tcp_accelerator_basics.git
$ cd pq_tcp_accelerator_basics
$ make -B

```

### Code of Conduct  :fire:
##### Create New Branch

*  Always create a branch from the ``` Latest Unstable Branch ``` or the `Feature Branch` you are working on.

##### Naming,

> (branch no * 100).(development branch sequence number)
>``` Ex: 100.0,100.1 for 1.0 branch ```
* Add Branch name, reason, your name,communication channel (Optional) to ` Development Branches ` table of `README.md`(AKA me :smirk:)

##### Join Existing Branch
* Add your name to ` Development Branches ` table of `README.md`

##### Commit local changes
* First create or pick a task from ``` Work Group Task ``` relevant to you (Bitrix Task Dashboard)
* Do your changes related to the task. Make sure the task is completed.
* Make sure you have added ```node_modules```  to ```.gitignore``` if you are working on nodejs based application.
* Add files to git.
```sh
$ git add .
```
* Commit each task to local git.
```sh
$ git commit -m "<Commit Message>"
```

### Commit Message ``` !Important! ```

> ##### #Bitrix Task Number - Commit Type : Task name from bitrix or your message
Ex: `#1111 - BugFix : Whatever`

#### Commit Types
* ` Enhancement `
* ` BugFix `
* ` Feature `

* After completing a task or a set of task, push code to remote git.
```sh
$ git push origin <Branch you are working on>
```
##### Merge Branches
###### Hierarchy
> master Branch (Latest Stable)
>
> > Main Branches
> >
> > > Feature Branches
> > >
> > > > Development Branches

###### Merge Requests
* Please make sure to merge only when your part is completed and done with developer testing. :relieved:
* Go to  ***repository -> branch -> Merge Request Button of your branch***
* Select immediate super branch as Target Branch. Ex: 3.1 for 310.5 developer branch
* Make sure to provide proper merge request message and submit.

License
----

Paraqum


**Free Software, Hell Nope!**
