document.querySelectorAll(".copy").forEach(function(btn){
  btn.addEventListener("click", function(){
    var el = document.querySelector(btn.dataset.copy);
    if(!el) return;
    var done = function(){
      var was = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(function(){ btn.textContent = was; }, 1400);
    };
    if(navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(el.textContent.trim()).then(done, function(){});
    } else {
      var r = document.createRange(); r.selectNodeContents(el);
      var s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
      try { document.execCommand("copy"); done(); } catch(e){}
    }
  });
});
