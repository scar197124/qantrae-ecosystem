
(function(){
  const app=document.querySelector('.app');
  const infoWrap=document.getElementById('itInfoPages');
  const tabs=[...document.querySelectorAll('[data-it-page]')];
  function show(page){
    tabs.forEach(btn=>{
      const on=btn.dataset.itPage===page;
      btn.classList.toggle('active',on);
      if(on)btn.setAttribute('aria-current','page');else btn.removeAttribute('aria-current');
    });
    if(page==='scanner'){
      if(app)app.hidden=false;
      if(infoWrap)infoWrap.hidden=true;
    }else{
      if(app)app.hidden=true;
      if(infoWrap){
        infoWrap.hidden=false;
        infoWrap.querySelectorAll('[data-it-info]').forEach(sec=>sec.hidden=sec.dataset.itInfo!==page);
      }
    }
    window.scrollTo({top:0,behavior:'smooth'});
  }
  tabs.forEach(btn=>btn.addEventListener('click',()=>show(btn.dataset.itPage)));
})();
