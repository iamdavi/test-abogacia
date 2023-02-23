import { defineStore } from "pinia";

export const testType = defineStore("testType", {
  state: () => ({
    type: undefined,
    year: undefined,
    modality: undefined,
    disableButton: true,
    step: 0,
  }),

  actions: {
    setType(type, year = undefined) {
      this.type = type;
      this.year = year;
      this.disableButton =
        type == undefined || (type == "year" && year == undefined);
    },
    nextStep() {
      this.step += 1;
    },
  },
});
