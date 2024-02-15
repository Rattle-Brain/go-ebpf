# Go eBPF

![Go eBPF Logo](https://www.google.com/url?sa=i&url=https%3A%2F%2Fm.youtube.com%2Fwatch%3Fv%3DeZp_3EjJdnA&psig=AOvVaw20D4fmWOzUhpSgV13xQy-F&ust=1708085356355000&source=images&cd=vfe&opi=89978449&ved=0CBIQjRxqFwoTCIjh0vmnrYQDFQAAAAAdAAAAABAE)

Este repositorio es un proyecto de prueba diseñado para familiarizarse con la tecnología eBPF (Extended Berkeley Packet Filter) utilizando el lenguaje de programación Go.

## Descripción

La tecnología eBPF ha ganado popularidad en los últimos años debido a su capacidad para proporcionar un marco seguro y eficiente para la programación en el kernel de Linux. Permite a los desarrolladores escribir pequeños programas que se ejecutan en el kernel y pueden interceptar y modificar eventos del sistema en tiempo real, como el tráfico de red o eventos del sistema.

Este proyecto está destinado a proporcionar un punto de partida para aquellos que deseen explorar eBPF con Go. Proporciona ejemplos simples de cómo escribir programas eBPF utilizando Go y cómo cargarlos y ejecutarlos en el kernel.

## Funcionalidades

- Ejemplos de programas eBPF escritos en Go.
- Utilidades para cargar y gestionar programas eBPF en el kernel desde Go.

## Requisitos previos

- Go instalado en tu sistema.
- Acceso al código fuente del kernel de Linux (para compilar e instalar módulos BPF).

## Uso

1. **Clona el repositorio:**

   ```bash
   git clone https://github.com/Rattle-Brain/go-ebpf.git