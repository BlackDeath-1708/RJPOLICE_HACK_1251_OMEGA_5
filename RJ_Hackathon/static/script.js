const signinE1=document.getElementById("btn-sign-in");
const signupE1=document.getElementById("btn-sign-up");
const conE1=document.getElementById("form-container");
const toE1=document.getElementById("toggle-panel");

signinE1.addEventListener("click",()=>{
    conE1.classList.remove("active");
    toE1.classList.remove("active");
});

signupE1.addEventListener("click",()=>{
    conE1.classList.add("active");
    toE1.classList.add("active");
});
