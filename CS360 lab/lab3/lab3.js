document.addEventListener('DOMContentLoaded', function () {
  // Function to initialize modal functionality
  function initializeModal(imgId, modalId) {
      const img = document.getElementById(imgId);
      const modal = document.getElementById(modalId);
      const modalImg = modal.querySelector('.modal-content');
      const captionText = modal.querySelector('div');
      const closeSpan = modal.querySelector('.close');

      img.onclick = function() {
          modal.style.display = "block";
          modalImg.src = this.src;
          captionText.innerHTML = this.alt;
      }

      closeSpan.onclick = function() {
          modal.style.display = "none";
      }
  }

  // Initialize for each image-modal pair
  initializeModal('myImg1', 'myModal1');
  initializeModal('myImg2', 'myModal2');
  initializeModal('myImg3', 'myModal3');
  initializeModal('myImg4', 'myModal4');
  initializeModal('myImg5', 'myModal5');
  initializeModal('myImg6', 'myModal6');
  initializeModal('myImg7', 'myModal7');
  // Add more initializeModal calls as needed for additional images
});
