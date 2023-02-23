<script>
export default {
	
}
</script>

<template>
	<v-container class="h-100-vh mx-h-75 align-center d-flex">
		<v-row align="center">
			<v-col cols="12" class="main-box-col pa-5">
				<v-row>
					<v-col cols="6">
						<v-row align="center" class="d-flex align-center">
							<v-col cols="12">
								<v-expansion-panels class="mb-3">
									<v-expansion-panel class="transparent mb-3">
										<v-expansion-panel-title disable-icon-rotate>
											Materias comunes
											<template v-slot:actions>
												<v-icon icon="mdi-chevron-right">
												</v-icon>
											</template>
										</v-expansion-panel-title>
										<v-expansion-panel-text>
											Lorem ipsum dolor sit amet consectetur adipisicing elit. Placeat asperiores quis pariatur sed mollitia velit facere saepe laboriosam nemo quidem quia, iusto ratione nam animi odit tempore incidunt in aspernatur.
										</v-expansion-panel-text>
									</v-expansion-panel>
								<!-- </v-expansion-panels>
								<v-expansion-panels> -->
									<v-expansion-panel class="transparent mb-3">
										<v-expansion-panel-title disable-icon-rotate>
											Especialidad en penal
											<template v-slot:actions>
												<v-icon icon="mdi-chevron-right">
												</v-icon>
											</template>
										</v-expansion-panel-title>
										<v-expansion-panel-text>
											Lorem ipsum dolor sit amet consectetur adipisicing elit. Consequuntur dolorum accusamus suscipit voluptate aspernatur itaque veniam magni eaque nihil necessitatibus nisi, autem magnam iusto laborum recusandae expedita, quos officiis! Quibusdam?
										</v-expansion-panel-text>
									</v-expansion-panel>
									<v-expansion-panel class="transparent mb-3">
										<v-expansion-panel-title disable-icon-rotate>
											Especialidad en administrativo
											<template v-slot:actions>
												<v-icon icon="mdi-chevron-right">
												</v-icon>
											</template>
										</v-expansion-panel-title>
										<v-expansion-panel-text>
											Lorem ipsum dolor sit amet consectetur adipisicing elit. Consequuntur dolorum accusamus suscipit voluptate aspernatur itaque veniam magni eaque nihil necessitatibus nisi, autem magnam iusto laborum recusandae expedita, quos officiis! Quibusdam?
										</v-expansion-panel-text>
									</v-expansion-panel>
									<v-expansion-panel class="transparent mb-3">
										<v-expansion-panel-title disable-icon-rotate>
											Especialidad en mercantil
											<template v-slot:actions>
												<v-icon icon="mdi-chevron-right">
												</v-icon>
											</template>
										</v-expansion-panel-title>
										<v-expansion-panel-text>
											Lorem ipsum dolor sit amet consectetur adipisicing elit. Consequuntur dolorum accusamus suscipit voluptate aspernatur itaque veniam magni eaque nihil necessitatibus nisi, autem magnam iusto laborum recusandae expedita, quos officiis! Quibusdam?
										</v-expansion-panel-text>
									</v-expansion-panel>
								</v-expansion-panels>
							</v-col>
						</v-row>
					</v-col>
					<v-col cols="6">
						<v-card variant="outlined">
							<v-toolbar
								color="rgba(0, 0, 0, 0)"
							>
								<v-toolbar-title class="text-overline">
									N 1
								</v-toolbar-title>

								<template v-slot:append>
									<v-progress-circular
										model-value="20"
										color="indigo-darken-2"
									></v-progress-circular>
								</template>
							</v-toolbar>
							<v-card-text class="pt-0">
								<h4>Lorem ipsum dolor sit amet consectetur adipisicing elit. Ad labore reprehenderit animi nobis id assumenda cupiditate magni dignissimos itaque, inventore repudiandae blanditiis fugiat quas qui repellendus expedita voluptatem officiis dolores!</h4>
							</v-card-text>
							<v-card-actions class="justify-end">
								<v-btn variant="outlined">Siguiente</v-btn>
							</v-card-actions>
							<v-sheet
								class="mx-auto question-stepper"
								max-width="600"
							>
								<v-slide-group
									show-arrows
								>
									<v-slide-group-item
										v-for="n in 25"
										:key="n"
										v-slot="{ isSelected, toggle }"
									>
										<v-btn
											class="ma-2"
											:variant="isSelected ? undefined : 'outlined'"
											:color="isSelected ? 'brown-lighten-3' : 'transparent'"
											text-color="brown"
											@click="toggle"
										>
											{{ n }}
										</v-btn>
									</v-slide-group-item>
								</v-slide-group>
							</v-sheet>
						</v-card>
					</v-col>
				</v-row>
			</v-col>
		</v-row>
	</v-container>
</template>

<style scoped>
.question-stepper{
	background-color: transparent;
}

.transparent {
	background-color: transparent;
	color: white;
}
</style>