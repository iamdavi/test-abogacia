<script setup>
import { ref } from 'vue'
import SlideContentComponent from '@/components/home/SlideContentComponent.vue'

const slides = ref([
	{
		title: 'Todos los test',
		text: `Prueba tu conocimiento en todas las materias con test generales en 
			los que se mezclan preguntas de todas las modalidades disponibles.`,
		button: {
			text: 'comenzar',
			icon: '',
			path: ''
		}
	},
	{
		title: 'Test por año',
		text: `Prueba tu conocimiento en todas las materias con test generales en 
			los que se mezclan preguntas de todas las modalidades disponibles.`,
		button: {
			text: 'comenzar',
			icon: '',
			path: ''
		}
	},
	{
		title: 'Test por especialidad',
		text: `Prueba tu conocimiento en todas las materias con test generales en 
			los que se mezclan preguntas de todas las modalidades disponibles.`,
		button: {
			text: 'comenzar',
			icon: '',
			path: ''
		}
	}
])
</script>

<template>
	<v-container class="h-100-vh mx-h-75 align-center">
		<v-row align="center" class="h-100-vh">
			<v-col cols="5" class="d-flex align-center main-box-col">
				<h1 id="website-title" class="text-h2">
					Test de acceso <br> a la abogacía
				</h1>
			</v-col>
			<v-col cols="2" class="text-center">
				<v-divider id="main-divider" vertical></v-divider>
			</v-col>
			<v-col cols="5" class="main-box-col pa-5">
				<v-carousel
					:continuous="false"
					:show-arrows="false"
					hide-delimiter-background
					height="275"
				>
					<v-carousel-item
						v-for="(slide, i) in slides"
						:key="i"
					>
						<SlideContentComponent 
							:title="slide.title" 
							:text="slide.text" 
							:button="slide.button" 
						></SlideContentComponent>
					</v-carousel-item>
				</v-carousel>
			</v-col>
		</v-row>
		<v-row class="mt-n20">
			<v-col class="text-center">
				<v-btn 
					:ripple="false"
					size="large"
					variant="text"
					stacked 
					append-icon="mdi-chevron-down">
					más
				</v-btn>
			</v-col>
		</v-row>
	</v-container>
</template>

<style>
</style>