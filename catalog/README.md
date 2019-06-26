# sport items
sport items page is a web application which provides the list of game categories. each category contains corresponding items of that game or sport. users are provided with google oAuth2 for registration and authentication. Every user can access the page information but not allowed to manipulate the information. only authorized users can add, delete, or edit their own categories or items.


## Steps to  run project
1. installing the softwares
    1. install **vagrant 2.2.1** and **virtual box 5.1.30** in your system.   [clickhere](https://github.com/udacity/fullstack-nanodegree-vm) for instructions
    2. install **python3** [click here](https://realpython.com/installing-python/) for help
2. create directory
_FSND-Virtual-Machine\vagrant_
    1. place final project here
_FSND-Virtual-Machine\vagrant\finalproject_
    2. Clone the **fullstack-nanodegree-vm** repository in _vagrant_ folder
3. set up
    i) open cmd or powershell from the below directory
    _FSND-Virtual-Machine\vagrant_
    ii) run command
        * `vagrant up`
        * `vagrant ssh`
        * `cd /vagrant`
    iii) navigate to final project
        * `cd finalproject`
4. run the project over server
    * `python3 finalproject.py`
5. open project in browser(recomended chrome or firefox)
    * http//localhost:5000/home
## JSON  points
```
 http://localhost:5000/category/3/items.json
 http://localhost:5000/items.json
```
