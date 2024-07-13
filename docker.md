# Docker CheatSheet
Explicación a fondo en:
+ [Curso de Docker](https://github.com/elcaza/curso_docker/tree/master)

# Comandos básicos

~~~bash
# Listar qué imagenes se tienen en nuestra computadora
docker images

# Listar qué contenedores se se han corrido en nuestra computadora
docker ps -a

# Listar qué contenedores se están ejecutando actualmente
docker ps

# Crear un nuevo contenedor
docker run <imagen>

# Ejecutar un comando dentro de un contenedor que ya está corriendo
docker exec <imagen> <comando>

# Ejecutar un comando en modo interactivo dentro de un contenedor que ya está corriendo
docker exec -it <imagen> <comando>

# Detener un contenedor
docker stop <contenedor>

# Iniciar un contenedor anteriormente creado (Vuelve a jalar la configuración con la que fue creado)
docker start <contenedor>
~~~

## Ver contenedores que se están/han ejecutado

~~~bash
# Ver que contenedores se ejecutan en background
docker ps
# sudo docker run ubuntu sleep 3

# Ver todos los que contenedores se han ejecutado
docker ps -a
~~~

## Listar información de un contenedor

~~~bash
# Listar información a bajo nivel de una imagen
sudo docker run -d ubuntu sleep 60
sudo docker inspect id_image

# Ver imagenes que conforman una capa de docker
docker history ubuntu
~~~

## Revisar logs
~~~bash
# Checar logs de una imagen
docker logs id_image

# Checar los logs de una una imagen y quedarse esperando
docker logs -f id_image
~~~

## Descargar y crear contenedores
~~~bash
# Descarga una imagen
docker pull hello-world

# Crear un contenedor
docker run hello-world

# Crear un contenedor y eliminarse tras ejecutarse
docker run --rm ubuntu

# Ejecutar un contenedor y asignar un nombre
docker run --name hello_ubuntu ubuntu 
~~~

## Iniciar contenedores
~~~bash
# Abrir un contenedor que se ha cerrado
    # Obtenemos el ID
docker ps -a
    # Inicializamos la imagen
docker start -i <name/id>
    # If the container wasn't started with an interactive shell to connect to, you need to do this to run a shell:
docker exec -it <name/id> /bin/sh

# Entrar a un contenedor que está corriendo
docker ps
docker exec -it id_docker /bin/bash
~~~

## Detener contenedores
~~~bash
# Detener un contenedor
docker ps
docker stop id_name_contenedor 
~~~

## Borrar contenedores
Es necesario primero "detener" el contenedor
~~~bash
# Borrar contenedor
docker ps -a
docker rm <id_contenedor>

# Borrar todos los contenedores
docker rm $(docker ps -a -q)
~~~

## Borrar imagenes
Es necesario eliminar los contenedores asociados a esta imagen
~~~bash
# Borrar imagenes
sudo docker rmi <id_imagen>
~~~

## Entrar a un contenedor
~~~bash
# Entrar al contenedor en modo interactivo
docker run -it ubuntu

# Entrar al contenedor y ejecutar un comando
sudo docker run ubuntu echo "hello world!"
~~~

## Commits & Login a Dockerhub

### Cosas a tomar en cuenta para hacer login en cuenta de Docker
+  Tener el nombre correcto de la imagen
    + username/image

~~~bash
# Obtenemos id
docker ps -a

# Cambiar tag // Solo en caso de ser requerido
docker tag id_image username/image:1.0

# Hacer commit de una imagen de docker
docker commit id_image user/image:1.0
# user/image    1.0       6f5e2d0470ef   9 seconds ago   243MB

# Hacer login en docker
docker login --username=user

# Enviar imagen a Dockerhub
docker push username/image:1.0
~~~


# Comandos básicos de Dockerfile
## Compilar imagen
~~~bash
# Compilar imagen
docker build -t user/image .
docker build -t user/image /path/to/file

# Compilar imagen sin cache
docker build -t user/image:1.0 . --no-cache=true
~~~

## Docker cache
El cache de Docker es usado para no ejecutar los comandos una vez que estos ya se han ejecutado.

### Ejemplo
Podria causar problemas en instrucciones como:
~~~Dockerfile
# Config inicial
FROM debian
RUN apt-get update
RUN apt-get install -y git

# Config nueva
# cache
FROM debian
# cache
RUN apt-get update
# Estariamos instalando sin antes haber hecho un update, podría descargarse un paquete viejo
RUN apt-get install -y curl git vim

# Posible solución
FROM debian
RUN apt-get update && apt-get install -y \
    curl \
    git \
    vim

# Otra solucion
docker build -t user/image:1.0 . --no-cache=true
~~~

## Algunas implementaciones útiles de imagenes preconstruidas
~~~bash
# Ejecutar un servidor de NextCloud
docker run -p 8080:80 nextcloud

# Ejecutar un servidor de PHP
docker run -p 8080:80 php

# Ejecutar un servidor de PHP con una carpeta en especifico
docker run -p 80:80 --rm --name php-app -v "$PWD"/sitio:/var/www/html/ php:7.2-apache

# Ejecutar Mobile Security Framework
sudo docker run -it --name mobsf -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

    # Visit your localhost or IP on 8000 port
    localhost:8000
    ## Default user and password
    mobsf:mobsf
~~~
