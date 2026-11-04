function response(data,status=200,headers={}){
 return new Response(JSON.stringify(data),{
  status,
  headers:{
   "Content-Type":"application/json",
   "Cache-Control":"no-store",
   ...headers
  }
 });
}

async function sign(value,password){
 const key=await crypto.subtle.importKey(
  "raw",
  new TextEncoder().encode(password),
  {name:"HMAC",hash:"SHA-256"},
  false,
  ["sign","verify"]
 );
 const signature=await crypto.subtle.sign(
  "HMAC",key,new TextEncoder().encode(value)
 );
 return btoa(String.fromCharCode(...new Uint8Array(signature)))
  .replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}

function getCookie(request){
 const cookies=request.headers.get("Cookie")||"";
 const match=cookies.match(/(?:^|;\s*)birthday_session=([^;]+)/);
 return match?match[1]:null;
}

async function validSession(request,password){
 const token=getCookie(request);
 if(!token)return false;
 const parts=token.split(".");
 if(parts.length!==2)return false;

 try{
  const expiry=atob(parts[0]);
  if(!/^\d+$/.test(expiry)||Number(expiry)<Date.now())return false;
  return (await sign(parts[0],password))===parts[1];
 }catch(e){return false;}
}

export default {
 async fetch(request,env){
  const url=new URL(request.url);
  const path=url.pathname;

  if(path==="/api/login"){
   if(request.method!=="POST"){
    return response({success:false},405);
   }

   try{
    const body=await request.json();
    if(typeof body.password!=="string"||
       body.password.length>200){
     return response({success:false},400);
    }

    if(body.password!==env.BIRTHDAY_PASSWORD){
     return response({success:false},401);
    }

    const expiry=String(Date.now()+8*60*60*1000);
    const payload=btoa(expiry);
    const signature=await sign(payload,env.BIRTHDAY_PASSWORD);
    const token=payload+"."+signature;

    return response({success:true},200,{
     "Set-Cookie":
      `birthday_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800`
    });
   }catch(e){
    return response({success:false},400);
   }
  }

  // Halaman login boleh dibuka tanpa password
  if(path==="/"||path==="/index.html"){
   return env.ASSETS.fetch(request);
  }

  // Semua halaman dan file lainnya wajib login
  if(!(await validSession(request,env.BIRTHDAY_PASSWORD))){
   return new Response("Silakan login terlebih dahulu.",{
    status:401,
    headers:{"Content-Type":"text/plain"}
   });
  }

  return env.ASSETS.fetch(request);
 }
};
