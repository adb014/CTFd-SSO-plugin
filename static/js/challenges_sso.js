document.body.addEventListener("click", () => {
  CTFd.fetch("/api/v1/users/me", {
    method: "GET",
    credentials: "same-origin",
    headers: {"Accept": "application/json",},
  }).then((response) => {
    return response.json();
  }).then((response) => {
    if (! response.success)
      window.location =    
        CTFd.config.urlRoot +
        "/login?next=" +     
        CTFd.config.urlRoot +
        window.location.pathname +
        window.location.hash;     
  });                        
}, false);
