async function isSSOLoggedIn() {
  CTFd.fetch("/api/v1/users/me", {
    method: "GET",
    credentials: "same-origin",
    headers: {"Accept": "application/json",},
  }).then((response) => {
    return response.json();
  }).catch(() => {
    window.location =
      CTFd.config.urlRoot +
      "/login?next=" +
      CTFd.config.urlRoot +
      window.location.pathname +
      window.location.hash;
  });
}

setInterval(() = {
  Array.prototype.forEach.call(document.getElementsByClassName("challenge-button"), (chall) =>
      chall.addEventListener("click", isSSOLoggedIn); 
}, 100);

