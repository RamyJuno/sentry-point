<template>
  <NavigationBar />
  <div class="container">
    <IntroSection class="style-section" />
    <hr>
    <WhySentry id="WhySentry" class="style-section"/>
    <hr>
    <ContactSection id="contact" class="style-section-contact" />
  </div>
  <FooterBar />
</template>

<script>
import ContactSection from './components/ContactSection.vue';
import FooterBar from './components/html/FooterBar.vue';
import NavigationBar from './components/html/NavigationBar.vue';
import IntroSection from './components/IntroSection.vue';
import WhySentry from './components/WhySentry.vue';


export default {
  components: {
    NavigationBar, ContactSection, IntroSection, FooterBar, WhySentry
  }
}
</script>

<style>
@import url('https://fonts.googleapis.com/css2?family=Rubik:ital,wght@0,300..900;1,300..900&display=swap');

#app {
  font-family: "Rubik", serif;
  font-optical-sizing: auto;
  font-weight: 400;
  font-style: normal;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: left;
  color: #2c3e50;
}

.style-section {
  min-height: 93vh;
}

.style-section-contact {
  min-height: 55vh;
}

nav {
  padding: 30px;
}

nav a {
  font-weight: bold;
  color: #2c3e50;
}

nav a.router-link-exact-active {
  color: #42b983;
}
</style>
