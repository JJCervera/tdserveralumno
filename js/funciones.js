// función para controlar si el texto ingresado está en formato HEXADECIMAL
function isHex(h) {   //https://www.sitepoint.com/community/t/how-to-check-if-string-is-hexadecimal/162739/7
var a = parseInt(h,16);
return (a.toString(16) ===h.toLowerCase())
}

// funcion para ir pasando a mayúsculas a medida que se tipea en los cuadros de texto: https://stackoverflow.com/a/37617376/7246780
function upperCaseF(a){
    setTimeout(function(){
        a.value = a.value.toUpperCase();
    }, 1);
}

//Encrypt password by SHA
//return a hex string
function encryptString(value)
{
	//	return value;
     return byte2hex(coreOfSha(AddlenOfSHA1(value)));
}


//The function of encrypt password by SHA

//lowercase or uppercase//before is hexcase.
var lowerorupper = 0;
//ASCII or Unicode//before is chrsz
var ascoruni = 8;

//Calculate the SHA-1 of an array of big-endian words, and a bit length 

function coreOfSha(blockArray)
   {
   var basearray = blockArray;
   var otherarray = Array(80);
   var one =   1732584193;
   var two = -271733879;
   var three = -1732584194;
   var four =   271733878;
   var five = -1009589776;

   //encry 512 bytes everytime
   for(var i = 0; i < basearray.length; i += 16)   
      {
     var oldone = one;
     var oldtwo = two;
     var oldthree = three;
     var oldfour = four;
     var oldfive = five;

	
     for(var j = 0; j < 80; j++)   
     {
       if(j < 16) otherarray[j] = basearray[i + j];
       else otherarray[j] = moveleft(otherarray[j-3] ^ otherarray[j-8] ^ otherarray[j-14] ^ otherarray[j-16], 1);
      
       var t = modAddOfSha(modAddOfSha(moveleft(one, 5), sha1_ft(j, two, three, four)),
                        modAddOfSha(modAddOfSha(five, otherarray[j]), sha1_kt(j)));
       five = four;
       four = three;
       three = moveleft(two, 30);
       two = one;
       one = t;
     }

     one = modAddOfSha(one, oldone);
     two = modAddOfSha(two, oldtwo);
     three = modAddOfSha(three, oldthree);
     four = modAddOfSha(four, oldfour);
     five = modAddOfSha(five, oldfive);
   }
   return new Array(one, two, three, four, five);

}

//Perform the appropriate triplet combination function for the current iteration
function sha1_ft(test, one, two, three)
   {
   //test < 80
   if(test < 20) return (one & two) | ((~one) & three);
   if(test < 40) return one ^ two ^ three;
   if(test < 60) return (one & two) | (one & three) | (two & three);
   return one ^ two ^ three;
}

//Determine the appropriate additive constant for the current iteration

function sha1_kt(test)
   {
   return (test < 20) ?   1518500249 : (test < 40) ?   1859775393 :
          (test < 60) ? -1894007588 : -899497514;
}



//Add integers, wrapping at 2^32. This uses 16-bit operations internally to work around bugs in some JS interpreters.


function modAddOfSha(leftvalue, rightvalue)
   {
   var lowbyte = (leftvalue & 0xFFFF) + (rightvalue & 0xFFFF);
   var highbyte = (leftvalue >> 16) + (rightvalue >> 16) + (lowbyte >> 16);
   return (highbyte << 16) | (lowbyte & 0xFFFF);
}

//Bitwise rotate a 32-bit number to the left.

function moveleft(value, offset)
   {
   return (value << offset) | (value >>> (32 - offset));
}



//This function will add the len of string
function AddlenOfSHA1(str) {
   var nblk=((str.length+8)>>6)+1, blks=new Array(nblk*16);
   for(var i=0;i<nblk*16;i++)blks[i]=0;
   for(i=0;i<str.length;i++)
     blks[i>>2]|=str.charCodeAt(i)<<(24-(i&3)*8);
   blks[i>>2]|=0x80<<(24-(i&3)*8);
   blks[nblk*16-1]=str.length*8;
   return blks;
}



//Convert an array of big-endian words to a hex string.

function byte2hex(bytearray)
   {
   var hex_tab = lowerorupper ? "0123456789ABCDEF" : "0123456789abcdef";
   var hexstring = "";
   for(var i = 0; i < bytearray.length * 4; i++)
      {
     hexstring += hex_tab.charAt((bytearray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
                  hex_tab.charAt((bytearray[i>>2] >> ((3 - i%4)*8   )) & 0xF);
   }
   return hexstring;
}
