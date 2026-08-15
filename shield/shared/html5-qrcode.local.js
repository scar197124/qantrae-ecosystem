/* Proxuma local QR bridge — Safari-compatible QR camera fallback.
   Native BarcodeDetector is used when available. When unavailable, a jsQR compatibility
   decoder is loaded only after the user starts QR scanning. Camera frames are processed
   in-browser and are not sent to a scanning API. Manual paste remains available. */
(function(){
  if (window.Html5Qrcode && window.Html5Qrcode.__proxumaSafariCompat) return;

  const JSQR_CDN = "https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js";
  let jsQrLoadPromise = null;

  function loadJsQr(){
    if (window.jsQR) return Promise.resolve(true);
    if (jsQrLoadPromise) return jsQrLoadPromise;
    jsQrLoadPromise = new Promise((resolve, reject) => {
      const existing = document.querySelector('script[data-proxuma-jsqr="true"]');
      if (existing) {
        existing.addEventListener("load", () => resolve(!!window.jsQR), { once:true });
        existing.addEventListener("error", () => reject(new Error("jsQR compatibility decoder failed to load")), { once:true });
        return;
      }
      const script = document.createElement("script");
      script.src = JSQR_CDN;
      script.async = true;
      script.defer = true;
      script.dataset.proxumaJsqr = "true";
      script.onload = () => resolve(!!window.jsQR);
      script.onerror = () => reject(new Error("jsQR compatibility decoder failed to load"));
      document.head.appendChild(script);
    });
    return jsQrLoadPromise;
  }

  class Html5Qrcode {
    constructor(elementId){
      this.elementId = elementId;
      this.root = document.getElementById(elementId);
      this.stream = null;
      this.video = null;
      this.canvas = null;
      this.running = false;
      this._timer = null;
      this._detector = null;
      this._mode = null;
    }

    static getSupportedFormats(){ return ['QR_CODE']; }

    _message(text){
      if(!this.root) return;
      this.root.innerHTML = '<div style="padding:12px;border:1px solid rgba(36,255,114,.35);border-radius:14px;color:#fff;background:rgba(0,0,0,.25);font-size:14px;line-height:1.45">'+text+'</div>';
    }

    async _selectDecoder(){
      if('BarcodeDetector' in window){
        this._detector = new BarcodeDetector({formats:['qr_code']});
        this._mode = 'native';
        return;
      }
      this._message('Loading Safari-compatible QR decoder...');
      await loadJsQr();
      if(!window.jsQR) throw new Error('QR compatibility decoder unavailable');
      this._mode = 'jsqr';
    }

    async start(cameraConfig, config, onSuccess, onError){
      if(!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia){
        this._message('Camera access is not available in this browser. Paste the QR destination manually to scan fully offline.');
        throw new Error('Camera unavailable');
      }

      await this._selectDecoder();

      this.running = true;
      this.stream = await navigator.mediaDevices.getUserMedia({video: cameraConfig || {facingMode:'environment'}});
      this.video = document.createElement('video');
      this.video.setAttribute('playsinline','true');
      this.video.muted = true;
      this.video.srcObject = this.stream;
      this.video.style.width = '100%';
      this.video.style.maxWidth = '420px';
      this.video.style.borderRadius = '14px';

      this.canvas = document.createElement('canvas');
      this.canvas.style.display = 'none';

      if(this.root){
        this.root.innerHTML='';
        this.root.appendChild(this.video);
        this.root.appendChild(this.canvas);
      }

      await this.video.play();

      const scan = async () => {
        if(!this.running) return;
        try{
          let value = '';
          if(this._mode === 'native' && this._detector){
            const codes = await this._detector.detect(this.video);
            if(codes && codes.length) value = codes[0].rawValue || codes[0].rawData || '';
          } else if(this._mode === 'jsqr' && window.jsQR && this.canvas) {
            const w = this.video.videoWidth;
            const h = this.video.videoHeight;
            if(w && h){
              this.canvas.width = w;
              this.canvas.height = h;
              const ctx = this.canvas.getContext('2d', { willReadFrequently:true });
              ctx.drawImage(this.video, 0, 0, w, h);
              const imageData = ctx.getImageData(0, 0, w, h);
              const code = window.jsQR(imageData.data, w, h, { inversionAttempts: 'attemptBoth' });
              if(code && code.data) value = code.data;
            }
          }
          if(value) onSuccess && onSuccess(value, { rawValue:value, decoder:this._mode });
        }catch(e){
          onError && onError(String(e));
        }
        this._timer = setTimeout(scan, Math.max(100, 1000/((config && config.fps) || 8)));
      };

      scan();
    }

    async stop(){
      this.running = false;
      if(this._timer) clearTimeout(this._timer);
      this._timer = null;
      if(this.stream) this.stream.getTracks().forEach(t=>t.stop());
      this.stream = null;
      return Promise.resolve();
    }

    clear(){ if(this.root) this.root.innerHTML=''; }

    async scanFile(file, showImage){
      if('BarcodeDetector' in window){
        const detector = new BarcodeDetector({formats:['qr_code']});
        let bitmap;
        if('createImageBitmap' in window){ bitmap = await createImageBitmap(file); }
        else {
          bitmap = await new Promise((resolve,reject)=>{
            const img = new Image();
            img.onload=()=>resolve(img); img.onerror=reject;
            img.src=URL.createObjectURL(file);
          });
        }
        const codes = await detector.detect(bitmap);
        if(codes && codes.length) return codes[0].rawValue || codes[0].rawData || '';
      }

      await loadJsQr();
      if(!window.jsQR) throw new Error('QR compatibility decoder unavailable');

      const img = await new Promise((resolve,reject)=>{
        const image = new Image();
        image.onload=()=>resolve(image);
        image.onerror=reject;
        image.src=URL.createObjectURL(file);
      });

      const canvas = document.createElement('canvas');
      canvas.width = img.naturalWidth || img.width;
      canvas.height = img.naturalHeight || img.height;
      const ctx = canvas.getContext('2d', { willReadFrequently:true });
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = window.jsQR(imageData.data, canvas.width, canvas.height, { inversionAttempts:'attemptBoth' });
      if(code && code.data) return code.data;
      throw new Error('No QR code detected');
    }
  }

  Html5Qrcode.__proxumaSafariCompat = true;
  window.Html5Qrcode = Html5Qrcode;
})();
