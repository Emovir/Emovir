document.addEventListener('DOMContentLoaded', function() {
    // Handle phone number click
    const phoneLinks = document.querySelectorAll('.phone-link');
    phoneLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            window.location.href = `tel:${this.dataset.phone}`;
        });
    });

    // Handle audio playback when touching/clicking the photo
    const photos = document.querySelectorAll('.play-message');
    photos.forEach(photo => {
        photo.addEventListener('click', async function() {
            const contactId = this.dataset.contactId;
            const audioPlayer = document.querySelector(`#audio-${contactId}`);

            // Pause all other playing audio
            document.querySelectorAll('audio').forEach(audio => {
                if (audio !== audioPlayer) {
                    audio.pause();
                }
            });

            try {
                await audioPlayer.play();
            } catch (err) {
                console.error('Error playing audio:', err);
            }
        });
    });
});