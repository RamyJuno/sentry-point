<template>
    <div class="text-start">
        <!-- Contact -->
        <h1 class="mt-3">Contact</h1>
        <p>Une question? Une suggestion? N'hésitez pas à nous contacter via ce formulaire.</p>

        <form class="mt-5 container">
            <div class="mb-3">
                <label for="name" class="form-label">Nom (ou raison sociale) *</label>
                <input type="password" class="form-control style-input" id="name">
            </div>
            <div class="mb-3">
                <label for="email" class="form-label">Adresse Email *</label>
                <input type="email" class="form-control style-input" id="email" aria-describedby="email input">
            </div>
            <div class="mb-3">
                <label for="message_area" class="form-label">Message *</label>
                <textarea class="form-control style-input" id="message_area"></textarea>
            </div>
            <div class="text-center mt-4">
                <button type="submit" class="btn btn-success btn-lg style-input shadow">Envoyer</button>
            </div>
        </form>
    </div>
</template>

<script>
export default {
    name: "ContactSection"
}
</script>

<style scoped>
.container {
    max-width: 720px;
    margin-top: 10%;
    margin-bottom: 10%;
}

.style-input {
    border-radius: 0;
    border: 1px solid black
}

</style>