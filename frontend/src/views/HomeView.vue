<script setup>
import { testType } from '../stores/testType'

import AllTestSlideCompoent from  '../components/home/AllTestSlideComponent.vue'
import YearTestSlideCompoent from '../components/home/YearTestSlideComponent.vue'
import TypeTestSlideCompoent from '../components/home/TypeTestSlideComponent.vue'

const testTypeStore = testType()

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
					@update:model-value="testTypeStore.setType(undefined)"
				>
					<v-carousel-item >
						<AllTestSlideCompoent />
					</v-carousel-item>
					<v-carousel-item >
						<YearTestSlideCompoent />
					</v-carousel-item>
					<v-carousel-item >
						<TypeTestSlideCompoent />
					</v-carousel-item>
				</v-carousel>
				<v-btn 
					to="/test"
					class="main-white-button"
					:rounded="0" 
					:disabled="testTypeStore.disableButton"
					append-icon="mdi-chevron-right"
				>
					Comenzar
				</v-btn>
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