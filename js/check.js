
//The function of encrypt password by SHA

//lowercase or uppercase//before is hexcase.
var lowerorupper = 0;
//ASCII or Unicode//before is chrsz
var ascoruni = 8;

//Encrypt password by SHA
//return a hex string
function encryptString(value)
{
	//	return value;
     return byte2hex(coreOfSha(AddlenOfSHA1(value)));
}



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

var commentLen = 150;
function checkcomment(comment, len)
{
	var s=comment.length;
	
  if (s > len)
  {
      alert("<i18n:message key='check_comment2'/>");
      return false;
  }
  return true;
}

//add
function checkSpace(obj)
{
	if ( obj )
	{
		obj.value = obj.value.trim();
		if ( obj.value == "" )
		{
			return true;
		}
		else
		{
			return false;
		}
	}
}

function checkEmail(email)
{
	var reg = /^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$/;
	if ( email )
	{
		return reg.test(email);
	}
	else
	{
		return false;
	}
}

function checkSpecialCharactorWithoutAnd(obj)
{
	var regSpecial = /[\\\%"'><]+/;
	if ( obj )
	{
		if ( regSpecial.test(obj.value) )
		{
			return true;
		}
		else
		{
			return false;
		}
	}
}

function checkSpaceWithMiddle(obj)
{
	var regspace = /\s+/;
	if ( obj )
	{
		obj.value = obj.value.trim();
		if ( obj.value == "" )
		{
			return true;
		}
		else if ( regspace.test(obj.value) )
		{
			return true;
		}
	}
	
	return false;
}

function checkSpecialCharactor(obj)
{
	var regSpecial = /[\\\%"'><&]+/;
	if ( obj )
	{
		if ( regSpecial.test(obj.value) )
		{
			return true;
		}
		else
		{
			return false;
		}
	}
}

function checkdigital(head,value)
{
	//alert("*" + value + "*");
    var patrn=/^[0-9]{1,30}$/;
	value = trim(value);
//	alert("*" + v + "*");
   
	if (!patrn.exec(value))
    {
	  	alert("<i18n:message key='check_tick_digit'/>");
      return false;
    }
	if (head == "Page")
	{
		document.form1.pages.value = value;
	}
	return true;
}

//according to the rule of password, restrict the password
function checkPassword(pwd)
{
	var passLen = pwd.length;
	for (var m=0; m<passLen; m++)
	{
		if (pwd.charCodeAt(m) > 127)
		{			
			alert("<i18n:message key='check_pwd_illegal'/>");
			return false;
		}
	}
   //alert(pwd);
   if (pwd.length < 6)
   {
   		alert("<i18n:message key='check_pwd_leng'/>");
			return false;		
   }
   var result = pwd.search(/[a-z]/);
   if (result == "-1")
   {
   		alert("<i18n:message key='check_pwd_lower'/>");
			return false;
   }
   result = pwd.search(/[A-Z]/);
   if (result == "-1")
   {
   		alert("<i18n:message key='check_pwd_upper'/>");
			return false;
   }
   result = pwd.search(/[\W]/);
   if (result == "-1")
   {
   		alert("<i18n:message key='check_pwd_spec'/>");
			return false;
   }   
   return true;
}

function checkifnull(name, value, note)
{
  if (value == "")
  {
  	if(name == "User name")
  	{
  		alert("<i18n:message key='check_username_null'/>");
  	}
  	else if(name == "Operator ID")
	{
		alert("<i18n:message key='check_input_opername'/>");
	}
	else if(name == "Password")
	{
		alert("<i18n:message key='check_pwd_null'/>");
	}
	else if(name == "New password")
	{
		alert("<i18n:message key='check_newpwd_null'/>");
	}
	else if(name == "Hardware ID")
	{
		alert("<i18n:message key='check_hwid_null'/>");
	}
	else if(name == "Student ID")
	{
		alert("<i18n:message key='check_stuid_null'/>");
	}
	else if(name == "Owner Name")
	{
		alert("<i18n:message key='check_ownername_null'/>");
	}
	else if(name == "Boot Tick")
	{
		alert("<i18n:message key='key_input_boottick'/>");
	}
	else if(name == "Date of Birth")
	{
		alert("<i18n:message key='check_birthday_null'/>");
	}
	else if(name == "Translation Equation")
	{
		alert("<i18n:message key='check_equation_null'/>");
	}
	else if(name == "Preserved Days")
	{
		alert("<i18n:message key='check_preservedays_null'/>");
	}
    return false;
  }
  return true;
}

function checkillegal(name, value)
{
  var illegalChars = /\W/;
  if (illegalChars.test(value))
  {
  		if(name == "Owner Name")
		{
			alert("<i18n:message key='check_name_illegal'/>");
		}
		else if(name == "Operator ID")
		{
			alert("<i18n:message key='check_oper_illegal'/>");
		}
		else if(name == "User name")
		{
			alert("<i18n:message key='check_user_illegal'/>");
		}
      return false;
  }
  return true;
}

function checkspaceok(name, value)
{
  var rightChars = /[^a-zA-Z0-9_ ]/;
 
  if (rightChars.test(value))
  {
  	//alert(name +  " must be 1234..,space, _, or abcd..., ABC...");
    return false;	
  }
  return true;		
}

function checkconfirm(pass, firm)
{
	if (pass!=firm )	
	{
		alert("<i18n:message key='check_pwd_inconsistent'/>");
		return false;
	}
	return true;
}

function checksuperform(frm)
{
	var ifnull, illegal;
        ifnull = checkifnull("Operator ID", frm.operatorName.value, "input");
        if (ifnull != true)
        {
          return false;
        }
		
		var name = frm.operatorName.value.toLowerCase();
		if (name == "system")
		{
			alert("<i18n:message key='opr_not_system'/>");
			return false;
		}
        //allow only letters, numbers, and underscores
        illegal = checkillegal("Operator ID", frm.operatorName.value);
        if (illegal != true)
        {
          return false;
        }
		
        ifnull = checkifnull("Password", frm.newPassword.value, "input");
        if (ifnull != true)
        {
          return false;
        }
        ifconfirm = checkconfirm(frm.confirmpwd.value, frm.newPassword.value)
        if (ifconfirm != true)
        {
          return false;
        }
	//restrict rule
        illegal = checkPassword(frm.newPassword.value);			
        if (illegal != true)
        {
          return false;
        }			
			
        return checkcomment(frm.operatorComment.value , commentLen);
}

//add by zhanghui 2007-9-13
function checkpsw(frm)
{
	 ifnull = checkifnull("Password", frm.newPassword.value, "input");
        if (ifnull != true)
        {
          return false;
        }
        ifconfirm = checkconfirm(frm.confirmpwd.value, frm.newPassword.value)
        if (ifconfirm != true)
        {
          return false;
        }
	//restrict rule
        illegal = checkPassword(frm.newPassword.value);			
        if (illegal != true)
        {
          return false;
        }			
		return true;
}

function checksupermodi(frm)
{
	var ifnull, illegal;
        ifnull = checkifnull("Operator ID", frm.operatorName.value, "input");
        if (!ifnull)
        {
          return false;
        }
        //allow only letters, numbers, and underscores
        illegal = checkillegal("Operator ID", frm.operatorName.value);
        if (!illegal)
        {
          return false;
        }
		
/*	if (frm.isChange.checked == "1")
	{
		ifnull = checkifnull("Password", frm.newPassword.value, "input");
		if (!ifnull)
		{
		  return false;
		}
		ifconfirm = checkconfirm(frm.confirmpwd.value, frm.newPassword.value)
		if (!ifconfirm)
		{
		  return false;
		}
		//restrict rule
		illegal = checkPassword(frm.newPassword.value);			
		if (illegal != true)
		{
		  return illegal;
		}								
	} */

        return checkcomment(frm.operatorComment.value , commentLen);
}
	 


function checkuserform(frm)
{
    return checkcomment(frm.comment.value , commentLen);
}

function checkpcform(frm)
{
	//check
        var ifnull, illegal;
	//check hardware id's format
        ifnull = checkifnull("Hardware ID", frm.HWID.value, "input");
        if (!ifnull)
        {  
          return false;
        }

        //allow only numbers
        illegal = checkMAC(frm.HWID.value);
        if (!illegal)
        {
          return false;
        }
		
	if (frm.HWID.value.length < 12)
	{
		alert("<i18n:message key='check_hwid'/>");
		return false;
	}
        //check student id, not null
        frm.ownerID.value = trim(frm.ownerID.value);
      /*  ifnull = checkifnull("Student ID", frm.ownerID.value, "input");
        if (!ifnull)
        {
          //return false;
        }
        */
        if(frm.ownerID.value != "" && frm.ownerID.value != null)
    {
    	illegal = checkpercent("Student ID", frm.ownerID.value);
    	if(!illegal)
    	{
    		return false;
    	}
    }
		
        //check nowner name
        frm.ownerName.value = trim(frm.ownerName.value);
      /*  ifnull = checkifnull("Owner Name", frm.ownerName.value, "input");
        if (!ifnull)
        {
          //return false;
        }
        */
		    if(frm.ownerName.value != "" && frm.ownerName.value != null)
		    {
		    	illegal = checkpercent("Owner Name", frm.ownerName.value);
		    	if(!illegal)
		    	{
		    		return false;
		    	}
		    }
    
        //check boot tick
      /*  ifnull = checkifnull("Boot Tick", frm.bootTick.value, "input");
        if (!ifnull)
        {
          return false;
        }
        */
        //
        //allow only numbers
  /*      illegal = checkdigital("Boot Tick", frm.bootTick.value);
        if (!illegal)
        {
          return false;
        }
        
        //check boot tick
        ifnull = checkifnull("Date of Birth", frm.ownerBirthday.value, "input");
        if (!ifnull)
        {
          return false;
        }
        
        if (frm.ownerBirthday.value != "")
        {        
        	illegal = checkBirthday(frm.ownerBirthday.value);     
	        if (illegal != true)
	        {
	        	return illegal;
	        }    
        }
        */
        return checkcomment(frm.deviceComment.value , commentLen);
        
        return true;
}

function checkstuform(frm)
{
	//check
        var ifnull, illegal;
	//check hardware id's format
        ifnull = checkifnull("Hardware ID", frm.HWID.value, "input");
        if (!ifnull)
        {  
          return false;
        }

        //allow only numbers
        illegal = checkMAC(frm.HWID.value);
        if (!illegal)
        {
          return false;
        }
		
				if (frm.HWID.value.length < 12)
				{
					alert("<i18n:message key='check_hwid'/>");
					return false;
				}
        //check student id, not null
    /*    frm.ownerID.value = trim(frm.ownerID.value);
        ifnull = checkifnull("Student ID", frm.ownerID.value, "input");
        if (!ifnull)
        {
          return false;
        }
        
        if(frm.ownerID.value != "")
		    {
		    	illegal = checkpercent("Student ID", frm.ownerID.value);
		    	if(!illegal)
		    	{
		    		return false;
		    	}
		    }
		*/
        //check nowner name
        frm.ownerName.value = trim(frm.ownerName.value);
        ifnull = checkifnull("Owner Name", frm.ownerName.value, "input");
        if (!ifnull)
        {
          return false;
        }
        
		    if(frm.ownerName.value != "")
		    {
		    	illegal = checkpercent("Owner Name", frm.ownerName.value);
		    	if(!illegal)
		    	{
		    		return false;
		    	}
		    }
        
		  frm.ownerBirthday.value = trim(frm.ownerBirthday.value);
        if(frm.ownerBirthday.value == null || frm.ownerBirthday.value == "")
		{
			alert("<i18n:message key='check_birthday_null'/>");
			return false;
		}
        if (frm.ownerBirthday.value != "")
        {        
        	illegal = checkBirthday(frm.ownerBirthday.value);     
	        if (illegal != true)
	        {
	        	return illegal;
	        }    
        }
        return true;
}

function checkpcquery(frm)
{
  	var illegal;
  	frm.HWID.value = trim(frm.HWID.value);
  	if(frm.HWID.value != "")
  	{
				illegal = checkMAC(frm.HWID.value);
				//alert("checkpcquery:"+frm.HWID.value);
				if (!illegal)
				{
				    return false;
				}
    }
    
    frm.ownerName.value = trim(frm.ownerName.value);
    if(frm.ownerName.value != "" && frm.ownerName.value != null)
    {
    	illegal = checkpercent("Owner Name", frm.ownerName.value);
    	if(!illegal)
    	{
    		return false;
    	}
    }
/*
   frm.ownerID.value = trim(frm.ownerID.value);
    if(frm.ownerID.value != "")
    {
    	illegal = checkpercent("Student ID", frm.ownerID.value);
    	if(!illegal)
    	{
    		return false;
    	}
    }
	/*	frm.startDate.value = trim(frm.startDate.value);
        if (frm.startDate.value != "")
        {        
        	illegal = checkDate(frm.startDate.value);  
	        if (illegal != true)
	        {
	        	return illegal;
	        }    
        }
       frm.endDate.value = trim(frm.endDate.value);
        if (frm.endDate.value != "")
        {
        	illegal = checkDate(frm.endDate.value);
	        if (illegal != true)
	        {
	        	return illegal;
	        }
        }           
        //check start date early than end date
        illegal = checkStartBeforeEnd(frm.startDate.value,frm.endDate.value);   
        if(illegal != true)
        {
        	return illegal;
        }       
        */  
        return true;
}
//check the format of date
function checkDate(dateValue)
{
	if(dateValue == "<i18n:message key='date_format'/>")
	{
		return true;
		
	}
	if (dateValue.length < 10)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	var restr = /[^0-9-]/;
	
	if (restr.test(dateValue))
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	var values = dateValue.split("-");
	if (values == null || values.length != 3)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	

	var month = values[1];
	var day = values[0];
	var year = values[2];
	
	if(month.length != 2)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	if(day.length != 2)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	if(year.length != 4)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	
	if (month < 1 || month > 12)
	{
		alert("<i18n:message key='check_date_month'/>");
		return false;
	}
	
	if ((month == 1 || month == 3 || month == 5 || month == 7 || month == 8 || month == 10 || month == 12) && (day < 1 || day > 31))
	{
		alert("<i18n:message key='check_date_day1'/>");
		return false;
	}
	
	 
	 if(month == 2 && ((year % 4 == 0 && year % 100 != 0) || (year % 100 == 0 && year % 400 == 0)) && (day < 1 || day > 29))
	{
		alert("<i18n:message key='check_date_day2'/>");
		return false;
	}
	if(month == 2 && !((year % 4 == 0 && year % 100 != 0) || (year % 100 == 0 && year % 400 == 0)) && (day < 1 || day > 28))
	{
		alert("<i18n:message key='check_date_day3'/>");
		return false;
	}
	if ((month == 4 || month == 6 || month == 9 || month == 11)  && (day < 1 || day > 30))
	{
		alert("<i18n:message key='check_date_day4'/>");
		return false;
	}

	if (year < 2000 || year > 2099)
	{
		alert("<i18n:message key='check_year_bound'/>");
		return false;
	}		
	//judge if the date is right
	var testDate = new Date(year, month-1, day);
	var testYear = testDate.getFullYear();
	var testMonth = testDate.getMonth()+1;
	var testDay = testDate.getDate();
	//alert(testYear);
	//alert(testMonth);
	//alert(testDay);
	
	if (testYear==year && testMonth== month && testDay== day)
	{
		return true;
	}
	else
		{
			alert("<i18n:message key='check_date_wrong'/>");
			return false;
		}	
	
}

function checkloginform(frm)
{
  var ifnull, illegal;

  ifnull = checkifnull("User name", frm.operatorName.value, "input");
  if (!ifnull)
  {
    return ifnull;
  }
  //allow only letters, numbers, and underscores
  illegal = checkillegal("User name", frm.operatorName.value);
  if (!illegal)
  {
    return illegal;
  }

  ifnull = checkifnull("Password", frm.password.value, "input");
  if (!ifnull)
  {
    return ifnull;
  }
  
  return true;
}

function checkmodipwd(frm)
{
  var ifnull, illegal;
  document.all.password.value=document.all.password2.value;
  ifnull = checkifnull("User name", frm.operatorName.value, "input");
  if (!ifnull)
  {
    return ifnull;
  }
  //allow only letters, numbers, and underscores
  illegal = checkillegal("User name", frm.operatorName.value);
  if (!illegal)
  {
    return illegal;
  }

  ifnull = checkifnull("Password", frm.password.value, "input");
  if (!ifnull)
  {
    return ifnull;
  }
  

  ifnull = checkifnull("New password", frm.newPassword.value, "input");
  if (!ifnull)
  {
    return ifnull;
  }
  //restrict rule
	illegal = checkPassword(frm.newPassword.value);			
	if (!illegal)
	{
	  return illegal;
	}		

  if(frm.newPassword.value != frm.confirmPassword.value )
  {
      alert("<i18n:message key='check_pwd_inconsistent'/>");
      return false;
  }
  return true;
}

//judge if want to chang password
function changePwd(frm)
{
	if (frm.isChange.checked == "1")
	{
		document.all.pwdarea.style.visibility = "visible";		
		document.all.confirmpwd.value = "";
		document.all.newPassword.value = "";
	}
	else
	{
		document.all.pwdarea.style.visibility = "hidden";	
		document.all.confirmpwd.value = "";
		document.all.newPassword.value = "";
	}
}

function adminReset()
	{		
		document.form1.reset();			
		document.all.isChange.checked = false;
		document.all.pwdarea.style.visibility = "hidden";
		document.all.confirmpwd.value = "";
		document.all.newPassword.value = "";	
	}


function trim(str)
{
	var theChar;
	var theLen;
	
	while(str!="")
	{
		theChar=str.charAt(0);
		if (theChar!=" ")
			break;
		else
		{
			theLen=str.length;
			if(theLen>1)
			{	str=str.substring(1,theLen);}
			else
				str="";				
		}
	}
	
	while(str!="")
	{
		theLen=str.length;
		theChar=str.charAt(theLen-1);
		if (theChar!=" ")
			break;
		else
		{
			
			if(theLen>1)
				
				str=str.substring(0,theLen-1);
			else
				str="";				
		}
	}
	return (str);
}

//judge if want to chang password
function changeExpirDate(frm)
{
	//alert(frm.checked);
	//alert(frm.name);
	//alert(frm.value);
	
	if (frm.value == 1)//if (frm.checked == true)
	{
		document.all.pwdarea.style.visibility = "visible";		
		document.all.password.value = "";
	}
	else
	{
		document.all.pwdarea.style.visibility = "hidden";	
		document.all.password.value = "";
	}
}


function checkspecercheck(frm)
{
      	var illegal;
        illegal = checkillegal("Hardware ID", frm.HWID.value);
        if (!illegal)
        {
          return illegal;
        }
        
        return true;
}

function checkkeyquery(frm)
{
  	var illegal;
  	frm.HWID.value = trim(frm.HWID.value);
    if(frm.HWID.value != "")
  	{
        illegal = checkMAC(frm.HWID.value);
        if (!illegal)
        {
          return false;
        }
    }   
    frm.ownerID.value = trim(frm.ownerID.value);
    if(frm.ownerID.value != "")
    {
    	illegal = checkpercent("Student ID", frm.ownerID.value);
    	if(!illegal)
    	{
    		return false;
    	}
    }     
    return true;
}

function checkboottick(frm)
{
   var ifnull;
		//check hardware id's format
        ifnull = checkifnull("Boot Tick", frm.bootTick.value, "input");
        if (!ifnull)
        {
          return ifnull;
        }
}


function checkcomcer(frm)
{
	// trim the space.
	var times = frm.bootTimes.value;
	times = times.replace(/(^\s*)|(\s*$)/g, "");
	frm.bootTimes.value = times;

	var expvalue = frm.expireDays.value;
	expvalue = expvalue.replace(/(^\s*)|(\s*$)/g, "");
	frm.expireDays.value = expvalue;

	var illegal, ifnull;
	ifnull = checkifnull("Translation Equation",times, "input");
	if (!ifnull)
        {
          return false;
        }
	      
        illegal = checkdigital("Translation Equation", times);
        if (!illegal)
        {
          return false;
        }
        
        ifnull = checkifnull("Preserved Days",expvalue, "input");
	      if (!ifnull)
        {
          return false;
        }
        
        illegal = checkdigital("Preserved Days", expvalue);
        if (!illegal)
        {
          return false;
        }        

	if(isNaN(times))
	{
		alert("<i18n:message key='check_tick_digit'/>");
		return false ; 
	}
	if(isNaN(expvalue))
	{
		alert("<i18n:message key='check_tick_digit'/>");
		return false ; 
	}

    /*    if(frm.bootTimes.value == "0" || frm.bootTimes.value == "00" || frm.bootTimes.value == "000")
        {
        	alert("<i18n:message key='com_boot_times_unzero'/>");
        	return false;
        }
        
        if(frm.expireDays.value == "0" || frm.expireDays.value == "00" || frm.expireDays.value == "000")
        {
        	alert("<i18n:message key='com_boot_days_unzero'/>");
        	return false;
        }
        */
		
	/*	var patrn=/^[1-9]*[1-9][0-9]*$/;   
		if (!patrn.exec(frm.bootTimes.value))
		{
			alert("<i18n:message key='check_tick_digit'/>");
			return false ; 
		}
		if (!patrn.exec(frm.expireDays.value))
		{
			alert("<i18n:message key='check_tick_digit'/>");
			return false ; 
		}*/
        //check if the days X times bigger than 365000
        var iTimes = Number(times);
        var iDays = Number(expvalue);
        
        // set times >= 100 and days >=15
        //if(iTimes * iDays < 100 || iDays < 15)
        //{
        //	alert("<i18n:message key='edit_spec_check_counter_min'/>");
        //	return false;
        //}
        
        var bootcounter = iTimes * iDays;
        if(bootcounter > 365000)
        {
        	alert("<i18n:message key='edit_spec_check_counter'/>");
        	return false;
        }
		frm.totalBootTimes.value = bootcounter;
        return true;
}

function checkspecialcer(frm)
{
	var illegal;
	frm.HWID.value = trim(frm.HWID.value);
      if(frm.HWID.value != "")
			{
        illegal = checkMAC(frm.HWID.value);
        if (!illegal)
        {
          return false;
        }
      }  
      frm.ownerName.value = trim(frm.ownerName.value);   
      if(frm.ownerName.value != "")
	    {
	    	illegal = checkpercent("Owner Name", frm.ownerName.value);
	    	if(!illegal)
	    	{
	    		return false;
	    	}
	    }
	/*    frm.ownerID.value = trim(frm.ownerID.value);  
	    if(frm.ownerID.value != "")
	    {
	    	illegal = checkpercent("Student ID", frm.ownerID.value);
	    	if(!illegal)
	    	{
	    		return false;
	    	}
	    }*/
      return true;
}

function checkspecerform(frm)
{
        var ifnull, illegal;
        
		    //check expiration date's format		
        ifnull = checkifnull("Expiration Date", frm.expirationDate.value, "input");
        if (!ifnull)
        {
          return ifnull;
        }
        
        illegal = checkDate(frm.expirationDate.value);
        if (!illegal)
        {
          return illegal;
        }
        
        //check boot times's format		
        ifnull = checkifnull("Translation Equation", frm.bootTimes.value, "input");
        if (!ifnull)
        {
          return ifnull;
        }
        
        illegal = checkdigital("Translation Equation", frm.bootTimes.value);
        if (!illegal)
        {
          return illegal;
        }
                
        return true;
}

//check the format of birthday
function checkBirthday(dateValue)
{
	var curdate = new Date();
	var curyear = curdate.getFullYear();
	if( 200>curyear)
	{
		curyear=curyear + 1900;
	}

	if (dateValue.length < 10)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	var restr = /[^0-9-]/;
	if (restr.test(dateValue))
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	var values = dateValue.split("-");
	if (values == null || values.length != 3)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	
	var month = values[1];
	var day = values[0];
	var year = values[2];
	
	if(month.length != 2)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	if(day.length != 2)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	if(year.length != 4)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	
	if (month < 1 || month > 12)
	{
		alert("<i18n:message key='check_date_month'/>");
		return false;
	}
	
	if ((month == 1 || month == 3 || month == 5 || month == 7 || month == 8 || month == 10 || month == 12) && (day < 1 || day > 31))
	{
		alert("<i18n:message key='check_date_day1'/>");
		return false;
	}
	
	 
	 if(month == 2 && ((year % 4 == 0 && year % 100 != 0) || (year % 100 == 0 && year % 400 == 0)) && (day < 1 || day > 29))
	{
		alert("<i18n:message key='check_date_day2'/>");
		return false;
	}
	if(month == 2 && !((year % 4 == 0 && year % 100 != 0) || (year % 100 == 0 && year % 400 == 0)) && (day < 1 || day > 28))
	{
		alert("<i18n:message key='check_date_day3'/>");
		return false;
	}
	if ((month == 4 || month == 6 || month == 9 || month == 11)  && (day < 1 || day > 30))
	{
		alert("<i18n:message key='check_date_day4'/>");
		return false;
	}
	
	if (year < 1900 || year > curyear)
	{
		
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}		
	//judge if the date is right
	var testDate = new Date(year, month-1, day);
	var testYear = testDate.getFullYear();
	var testMonth = testDate.getMonth()+1;
	var testDay = testDate.getDate();
	//alert(testYear);
	//alert(testMonth);
	//alert(testDay);
	if (testYear==year && testMonth== month && testDay== day)
	{
		//return true;
	}
	else
	{
		
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}	
	
	//check birthday can't later than today
	var illegalBirth = checkDateLaterToday(dateValue);
	if(!illegalBirth)
	{
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}
	else
	{
		return true;
	}
	
}

//check the format of date
function checkPermDate(dateValue)
{
	if (dateValue.length < 10)
	{
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}
	var restr = /[^0-9-]/;
	if (restr.test(dateValue))
	{
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}
	var values = dateValue.split("-");
	if (values == null || values.length != 3)
	{
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}
	

	var month = values[1];
	var day = values[0];
	var year = values[2];
	
	if(month.length != 2)
	{
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}
	if(day.length != 2)
	{
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}
	if(year.length != 4)
	{
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}
	
	if (month < 1 || month > 12)
	{
		alert("<i18n:message key='check_date_month'/>");
		return false;
	}
	
	if ((month == 1 || month == 3 || month == 5 || month == 7 || month == 8 || month == 10 || month == 12) && (day < 1 || day > 31))
	{
		alert("<i18n:message key='check_date_day1'/>");
		return false;
	}
	
	 
	 if(month == 2 && ((year % 4 == 0 && year % 100 != 0) || (year % 100 == 0 && year % 400 == 0)) && (day < 1 || day > 29))
	{
		alert("<i18n:message key='check_date_day2'/>");
		return false;
	}
	if(month == 2 && !((year % 4 == 0 && year % 100 != 0) || (year % 100 == 0 && year % 400 == 0)) && (day < 1 || day > 28))
	{
		alert("<i18n:message key='check_date_day3'/>");
		return false;
	}
	if ((month == 4 || month == 6 || month == 9 || month == 11)  && (day < 1 || day > 30))
	{
		alert("<i18n:message key='check_date_day4'/>");
		return false;
	}

	if (year < 2000 || year > 2099)
	{
		alert("<i18n:message key='check_year_bound'/>");
		return false;
	}		
	//judge if the date is right
	var testDate = new Date(year, month-1, day);
	var testYear = testDate.getFullYear();
	var testMonth = testDate.getMonth()+1;
	var testDay = testDate.getDate();
	//alert(testYear);
	//alert(testMonth);
	//alert(testDay);
	
	if (testYear==year && testMonth== month && testDay== day)
	{
		return true;
	}
	else
		{
			alert("<i18n:message key='check_date_wrong'/>");
			return false;
		}	
	
}

function checkStartBeforeEnd(startValue, endValue)
{
	var values1 = startValue.split("-");

	var month1 = values1[1];
	var day1 = values1[0];
	var year1 = values1[2];
	
	var values2 = endValue.split("-");

	var month2 = values2[1];
	var day2 = values2[0];
	var year2 = values2[2];
	
	//check start date early than end date
	if(year1 > year2)
	{
		alert("<i18n:message key='check_date_fromto'/>");
		return false;
	}else if((year1 == year2) && (month1 > month2))
	{
		alert("<i18n:message key='check_date_fromto'/>");
		return false;
	}else if((year1 == year2) && (month1 == month2) && (day1 > day2))
	{
		alert("<i18n:message key='check_date_fromto'/>");
		return false;
	}
	return true;	
}

function checktrackingquery(frm)
{
	  	 var illegal;
  		 frm.HWID.value = trim(frm.HWID.value);
       if(frm.HWID.value != "")
  	{
				illegal = checkMAC(frm.HWID.value);
				//alert("checkpcquery:"+frm.HWID.value);
				if (!illegal)
				{
				    return false;
				}
    }
	
	 frm.ownerID.value = trim(frm.ownerID.value);  
	    if(frm.ownerID.value != "")
	    {
	    	illegal = checkpercent("Student ID", frm.ownerID.value);
	    	if(!illegal)
	    	{
	    		return false;
	    	}
	    }
  /*  frm.networkIP.value = trim(frm.networkIP.value);
       if(frm.networkIP.value != "")
       {
	        illegal = checkIP("networkIP", frm.networkIP.value);
	        if (illegal != true)
	        {
	          return false;
	        }
      }
      frm.gatewayIP.value = trim(frm.gatewayIP.value);
       if(frm.gatewayIP.value != "")
       {
	        illegal = checkIP("gatewayIP", frm.gatewayIP.value);
	        
	        if (illegal != true)
	        {
	          return false;
	        }
      }
        frm.networkProxy.value = trim(frm.networkProxy.value);
        if(frm.networkProxy.value != "")
        {
	        illegal = checkIP("networkProxy", frm.networkProxy.value);
	        if (illegal != true)
	        {
	          return false;
	        }
     		}
     	
     	 frm.startDate.value = trim(frm.startDate.value);
        if (frm.startDate.value != "")
        {        
        	illegal = checkDate(frm.startDate.value);     
	        if (illegal != true)
	        {
	        	return illegal;
	        }    
        }
       frm.endDate.value = trim(frm.endDate.value);
        if (frm.endDate.value != "")
        {
        	illegal = checkDate(frm.endDate.value);
	        if (illegal != true)
	        {
	        	return illegal;
	        }
        }           
        //check start date early than end date
        illegal = checkStartBeforeEnd(frm.startDate.value,frm.endDate.value);   
        if(illegal != true)
        {
        	return illegal;
        }   
        frm.stolenStartDate.value = trim(frm.stolenStartDate.value);
        if (frm.stolenStartDate.value != "")
        {        
        	illegal = checkDate(frm.stolenStartDate.value);     
	        if (illegal != true)
	        {
	        	return illegal;
	        }    
        }
        frm.stolenEndDate.value = trim(frm.stolenEndDate.value);
        if (frm.stolenEndDate.value != "")
        {
        	illegal = checkDate(frm.stolenEndDate.value);
	        if (illegal != true)
	        {
	        	return illegal;
	        }
        }           
        //check start date early than end date
        illegal = checkStartBeforeEnd(frm.stolenStartDate.value,frm.stolenEndDate.value);   
        if(illegal != true)
        {
        	return illegal;
        }   */    
              
        return true;
}

function checklogquery(frm)
{
	var illegal;
  
  frm.operatorName.value = trim(frm.operatorName.value);
	illegal = checkillegal("Operator ID", frm.operatorName.value);
	if (illegal != true)
	{
	    return false;
	}
/*  frm.startDate.value = trim(frm.startDate.value);
  if (frm.startDate.value != "")
  {        
  	illegal = checkDate(frm.startDate.value);     
    if (illegal != true)
    {
    	return illegal;
    }    
  }
  
  frm.endDate.value = trim(frm.endDate.value);
  if (frm.endDate.value != "")
  {
  	illegal = checkDate(frm.endDate.value);
    if (illegal != true)
    {
    	return illegal;
    }
  }           
  //check start date early than end date
  illegal = checkStartBeforeEnd(frm.startDate.value,frm.endDate.value);   
  if(illegal != true)
  {
  	return illegal;
  }   */      
  return true;
}

function checkIP(name, ip) 
{
		if(ip.indexOf("%") >= 0 || ip.indexOf("\\") >= 0 || ip.indexOf("'") >= 0
		  || ip.indexOf("@") >= 0 || ip.indexOf("_") >= 0 || ip.indexOf(";") >= 0)
	{
		alertIPError(name);
		return false;
	}
	
	var ipLen = ip.length;
	for (var m=0; m<ipLen; m++)
	{
		if (ip.charCodeAt(m) > 127)
		{			
			alertIPError(name);
			return false;
		}
	}
	
	var arrip = ip.split(".");   
  if(arrip.length > 4)
  {
  	alertIPError(name);
  	return false;   
  }
  for(var i = 0; i < arrip.length; i++)
  {   
      n = parseInt(arrip[i], 10); 
      if(!(n.toString() == arrip[i] && n < 256 && n >= 0))
      {
      	alertIPError(name);
      	return false; 
      }
  }   
  
  return true;

}

function alertIPError(name)
{
	if(name == "networkIP")
		{
			document.form1.networkIP.focus();
		}
		else if(name == "gatewayIP")
		{
			document.form1.gatewayIP.focus();
		}
		else if(name == "networkProxy")
		{
			document.form1.networkProxy.focus();
		}
		//alert("<i18n:message key='check_ip_spec'/>");
		alert("<i18n:message key='check_ip_spec'/>");
}
function checkHWID(mac)
{
	var patrn=/^[0-9A-Fa-f]{1,30}$/; 
	if(!patrn.exec(mac))
	{
		alert("ERROR: controlá los valores del ID de HARDWARE.\n\nAyuda:\nLos valores están en sistema HEXADECIMAL\nLos valores posibles son del 0-9 y de la A-F\n\nun error común es confundir el 0 (cero) por una letra O\nsiendo que la letra O no es válida.\n\nNo ingreses los guiones - no espacios\nEj si dice 8B-6C-00-10-54-24 solo ingresa 8B6C00105424");
		return false;
	}
	return true;
}

// JJC Agregada funcion para check boot tick por el mensaje de alert.
function checkBT(mac)
{
	var patrn=/^[0-9A-Fa-f]{1,30}$/; 
	if(!patrn.exec(mac))
	{
		alert("ERROR: controlá los valores de la Marca de Arranque o 'Boot Tick'.\n\nAyuda:\nLos valores están en sistema HEXADECIMAL\nLos valores posibles son del 0-9 y de la A-F\n\nun error común es confundir el 0 (cero) por una letra O\nsiendo que la letra O no es válida.\n\nNo ingreses los guiones - no espacios\nEj si dice 00 00 1C solo ingresa 1C");
		return false;
	}
	return true;
}


//check the value can't include "%" and "\", ""","<",">"
function checkpercent(name,val)
{
	if(val.indexOf("%") >= 0 || val.indexOf("\\") >= 0 || val.indexOf("\"") >= 0
	    || val.indexOf("<") >= 0 || val.indexOf(">") >= 0 || val.indexOf("'") >=0)
	{
		if(name == "Owner Name")
		{
			alert("<i18n:message key='check_ownerid_illegal'/>");
		}
		else if(name == "Student ID")
		{
			alert("<i18n:message key='check_ownername_illegal'/>");
		}
		else if(name == "Migrate School")
		{
			alert("<i18n:message key='check_schoolname_illegal'/>");
		}
		return false;
	}
	return true;
}

function checkDateLaterToday(birthday)
{
	var values1 = birthday.split("-");

	var month1 = values1[1];
	var day1 = values1[0];
	var year1 = values1[2];

	//get current date
	var today = new Date(); 
	var year2 = today.getFullYear();
	if(200 > year2)
	{
		year2 = year2 + 1900;
	}
	var month2 = today.getMonth() + 1;//0-11
	var day2 = today.getDate();
	
	//check start date early than end date, without alert info
	if(year1 > year2)
	{
		return false;
	}else if((year1 == year2) && (month1 > month2))
	{
		return false;
	}else if((year1 == year2) && (month1 == month2) && (day1 > day2))
	{
		return false;
	}
	return true;	
}

function getFileName(obj) 
{
  if (obj) 
  {
	  if (window.navigator.userAgent.indexOf("MSIE") >= 1) 
	  {
	  	obj.select(); 
	  	var fName = document.selection.createRange().text;
	  	//alert("fName:"+ fName);
	  	if (fName.lastIndexOf("\\") > 0)
	  	{
	  		fName = fName.substring(fName.lastIndexOf("\\") + 1, fName.length);
	  	}
	  	return fName;
	  }
	  else if (window.navigator.userAgent.indexOf("Firefox") >= 1) 
	  {
		  if (obj.files) 
		  {
		  	//return obj.files.item(0).getAsDataURL();
		  	return obj.files.item(0).fileName;
		  }
		  return obj.value;
	  }
	  return obj.value;
	}
}
function CheckitFile()
{	
	var filepath=getFileName(document.getElementById("itfile"));
  //check if it is xml file or it is empty, by filename.
  if (filepath!="" )
  {
	var filename = filepath.toLowerCase();
	var pos = filename.lastIndexOf(".");
	var lastname = filename.substring(pos,filename.length);
	if(lastname.toLowerCase() == ".xml")
	{
		document.all.Pathfile.value=filename;
	}
	else
	{
		alert("<i18n:message key='import_note1'/>");
		return false;
	}
   document.all.ImportFile.submit();
  }
  else if (document.all.itfile.value=="" && document.all.hint!=null)
  {
   document.all.hint.style.visibility="hidden";
   alert("<i18n:message key='import_note1'/>");
   return false;
  }
  else if (document.all.itfile.value==""){
     alert("<i18n:message key='import_note1'/>");
     return false;
  }
  document.all.sub.alt = '';
  document.all.sub.disabled=1;
}

function CheckIntelFile()
{	
  //check if it is xml file or it is empty, by filename.
  var filepath=getFileName(document.getElementById("itfile"));
  if (filepath != "" )
  {
	var filename = filepath.toLowerCase();
	var pos = filename.lastIndexOf(".");
	var lastname = filename.substring(pos,filename.length);
	if(lastname.toLowerCase() == ".bin")
	{
			document.all.Pathfile.value = filepath;
	}
	else
	{
		alert("<i18n:message key='intel_import_warning'/>");
		return false;
	}
   document.all.ImportFile.submit();
  }
  else if (filepath == "" && document.all.hint!=null)
  {
   document.all.hint.style.visibility="hidden";
   alert("<i18n:message key='intel_import_warning'/>");
   return false;
  }
  else if (filepath == ""){
     alert("<i18n:message key='intel_import_warning'/>");
     return false;
  }
  document.all.sub.alt = '';
}

function checksetform(frm)
{
   var ifnull, illegal;

	if(frm.expirationDate.value == "" || frm.expirationDate.value == "<i18n:message key='date_format'/>")
	{
		alert("<i18n:message key='check_expdate_null'/> ");
		return false;
	}
   if(frm.checkFlag.checked == 0)
   {
	   illegal = checkPermDate(frm.expirationDate.value);
	   if (!illegal)
	   {
		  return illegal;
	   }
   }
  /* illegal = checkdigital("Translation Equation", frm.bootTimes.value);
   if (!illegal)
   {
      return illegal;
   }*/
   //check if the calculated boot counter is bigger than 999999.
   if(frm.specialFlag.value != "2")
   {
	   illegal = checkbootcounter(frm.expirationDate.value,frm.bootTimes.value);
	   if (!illegal)
	   {
		  return false;
	   }
   }
   return true;
}

function checkifCom(frm)
{
    question = confirm("<i18n:message key='edit_spec_to_common'/>");
		if (question != "0")
		{
			frm.specialFlag.value = "0";
			return true;
		}
		return false;
}

function checkbootcounter(expdate, times)
{   
	var curdate = new Date();
	var year = curdate.getYear();
	if(200 > year)
	{
		year = year + 1900;
	}

	var month = curdate.getMonth();//month is from 0 to 11
	var day = curdate.getDate();
	month = month + 1;
	var monthstr;
	monthstr = month;
	var datestr;
	datestr = day;
	var tempDate = monthstr + "-" + datestr + "-" + year;
    var   miStart   =   Date.parse(expdate.replace(/\-/g,   '/'));
	//alert("miStart: "+ miStart);   
    var   miEnd   =   Date.parse(tempDate.replace(/\-/g,   '/'));   
	//alert("miEnd: "+miEnd);  
    var   remaindays   =   (miStart-miEnd)/(1000*24*3600); 
	var expDays = parseFloat(remaindays) + 1;//if today is expiration date, the expiration days should be 1.
	//alert("remain days: " + expDays);
	//get expiration days
	var   result = expDays * times; 
	if(result > 365000)
	{
		alert("<i18n:message key='edit_spec_check_counter'/>");
		return false;
	} 
    return true;
}  
 
function checkquery()
{
    var illegal;
	query.query_name.value = trim(query.query_name.value);
    illegal = checkillegal("Operator ID", query.query_name.value);
    if (!illegal)
    {
      return false;
    }
    
    return true;
}

//added by zhanghui
function checkservice(frm)
{
	var obj=document.getElementsByName("service");
	var flag = 0;
	 for(i=0;i < obj.length;i++)
     {
			if(obj[i].checked)
			{
				flag=1;
			}
	 }
	 if (flag == 0)
	 {
	 	alert("Please choose the service status");
		return false;
	 }
	return true;
}

function CheckImportKeyFile()
{	
  //alert("aaa");
  //check if it is xml file or it is empty, by filename.
  if (document.all.itfile.value!="" )
  {
	document.all.Pathfile.value=document.all.itfile.value;
	var filename = document.all.itfile.value.toLowerCase();
	var pos = filename.lastIndexOf("/");
	var lastname = filename.substring(pos + 1,filename.length);
	//alert("lastname="+lastname);
	if(lastname.toLowerCase() == "serverkeyfile.zip")
	{
		//alert("pathfile="+document.all.Pathfile.value);
	}
	else
	{
		alert("<i18n:message key='keyfile_import_warning'/>");
		return false;
	}
   document.all.ImportFile.submit();
  }
  else if (document.all.itfile.value=="" && document.all.hint!=null)
  {
   document.all.hint.style.visibility="hidden";
   alert("<i18n:message key='keyfile_import_warning'/>");
   return false;
  }
  else if (document.all.itfile.value==""){
     alert("<i18n:message key='keyfile_import_warning'/>");
     return false;
  }
  document.all.sub.alt = '';
}

function checkmodifydevice(frm)
{
	frm.ownerBirthday.value = trim(frm.ownerBirthday.value);
        if(frm.ownerBirthday.value == null || frm.ownerBirthday.value == "<i18n:message key='date_format'/>")
				{
				//	alert("<i18n:message key='check_birthday_null'/>");
				//	return false;
				}
        else
        {   
        	var ille = checkBirthday(frm.ownerBirthday.value); 
	        if (ille != true)
	        {
	        	return illegal;
	        }    
        }

	var illegal = checkpcform(frm);
	if(!illegal)
	{
		return false;
	}
	return true;
}

function checkmigquery(frm)
{
  	var illegal;
  	frm.HWID.value = trim(frm.HWID.value);
  	if(frm.HWID.value != "")
  	{
		illegal = checkMAC(frm.HWID.value);
		//alert("checkpcquery:"+frm.HWID.value);
		if (!illegal)
		{
		    return false;
		}
    }
    frm.ownerID.value = trim(frm.ownerID.value);
    if(frm.ownerID.value != "" && frm.ownerID.value != null)
    {
    	illegal = checkpercent("Student ID", frm.ownerID.value);
    	if(!illegal)
    	{
    		return false;
    	}
    }

        return true;
}

//Add for Set Boot Count on UI
function setBootCounter()
{
var expObj = document.getElementById("exDate");
	//expObj.focus();
   var ifnull, illegal;

	if (expObj.value.length == 10)
	{
		illegal = checkExpireDate(document.getElementById("exDate").value);
		if (!illegal)
		   {
			  return false;
		   }
	}
	
var flag = document.getElementById("specialFlag").value;
//alert("falg:"+flag);
//expObj.focus();
   if(flag != "2")
   {
	   illegal = countbootcounterforBC(expObj.value);
	   if (!illegal)
	   {
		//alert("<i18n:message key='invalid_bootcounter'/>");
		//expObj.focus();
		  return false;
	   }
   }
   return true;
}

//this function is used for Portuguess that change boot counters on UI.
function checksetformBC(frm)
{
	var times = document.getElementById("bootCounters").value;
	times = times.replace(/(^\s*)|(\s*$)/g, "");
	document.getElementById("bootCounters").value = times;
	if(times == "")
	{
		alert("<i18n:message key='invalid_bootcounter'/>");
		return false;
//		var ret = setBootCounter();
//		if (!ret)
//		{
//			return ret;
//		}
	} 
	if (isNaN(times) || times <= 0)
	{
		alert("<i18n:message key='invalid_bootcounter'/>");
		  return false;
	}

var expObj = document.getElementById("exDate");
	//expObj.focus();
   var ifnull, illegal;

	if(frm.expirationDate.value == "" || frm.expirationDate.value == "<i18n:message key='date_format'/>")
	{
		alert("<i18n:message key='check_expdate_null'/> ");
		return false;
	}
   if(frm.checkFlag.checked == 0)
   {
	   illegal = checkSetCertDate(frm.expirationDate.value);//checkPermDate(frm.expirationDate.value);
	   if (!illegal)
	   {
		  return illegal;
	   }
   }

   //check if the calculated boot counter is bigger than 999999.
   if(frm.specialFlag.value != "2")
   {
	   illegal = checkbootcounterforBC(frm.expirationDate.value,frm.bootCounters.value);
	   if (!illegal)
	   {
		alert("<i18n:message key='invalid_bootcounter'/>");
		//expObj.focus();
		  return false;
	   }
   }
   return true;
}

//this function is used for Portuguess that change boot counters on UI.
function checkbootcounterforBC(expdate, counter)
{   

 var times = document.getElementById("bootCounters").value;
//times = times.trim();
times = times.replace(/(^\s*)|(\s*$)/g, "");
document.getElementById("bootCounters").value = times;

	if(times == "")
	{
		alert("<i18n:message key='invalid_bootcounter'/>");
		//expObj.focus();
		return false;
	} 

	if (isNaN(times) || times <= 0)
	{
		//alert("<i18n:message key='invalid_bootcounter'/>");
		//document.getElementById("exDate").focus();
		return false;
	}

	if(times > 365000)
	{
		//alert("<i18n:message key='edit_spec_check_counter'/>");
		//document.getElementById("exDate").focus();
		return false;
	} 
    return true;
}  

function countbootcounterforBC(expdate)
{   
var expObj = document.getElementById("exDate");
	var counter;
	var curdate = new Date();
	var year = curdate.getYear();
	if(200 > year)
	{
		year = year + 1900;
	}

	var month = curdate.getMonth();//month is from 0 to 11
	var day = curdate.getDate();
	month = month + 1;
	var monthstr;
	monthstr = month;
	var datestr;
	datestr = day;
	var tempDate = monthstr + "-" + datestr + "-" + year;
	
	//added to modify tracker 5442
	var expstr = expdate.split("-");

	var month1 = expstr[1];
	var day1 = expstr[0];
	var year1 = expstr[2];
	
	expdate = month1 + "-" + day1 + "-" + year1;
	//end of added
	
    var   miStart   =   Date.parse(expdate.replace(/\-/g,   '/'));
	//alert("miStart: "+ miStart);   
    var   miEnd   =   Date.parse(tempDate.replace(/\-/g,   '/'));   
	//alert("miEnd: "+miEnd);  
    var   remaindays   =   (miStart-miEnd)/(1000*24*3600); 
	var expDays = parseFloat(remaindays) + 1;//if today is expiration date, the expiration days should be 1.
	//alert("days:"+expDays);
	var comTimes = document.getElementById("comTimes").value;
	if (expDays <= 0)
	{
		if (year1.length < 4)
		{
			document.getElementById("bootCounters").value= "";
		}
		else
		{
			document.getElementById("bootCounters").value= "0";
		}
		counter = 0;
		//alert("<i18n:message key='invalid_bootcounter'/>");
		//expObj.focus();
		//return false;
	}
	else
	{
		counter = Math.floor(comTimes * expDays);
		if (isNaN(counter))
		{
			document.getElementById("bootCounters").value= "";
			counter = 0;
			//alert("<i18n:message key='invalid_bootcounter'/>");
			//expObj.focus();
			//return false;
		}
		else
		{
			document.getElementById("bootCounters").value= counter;
		}
	}

	if(counter > 365000)
	{
		alert("<i18n:message key='edit_spec_check_counter'/>");
		//expObj.focus();
		return false;
	} 
    return true;
}

//check the format of date
function checkExpireDate(dateValue)
{
	if(dateValue == "<i18n:message key='date_format'/>")
	{
		return true;
		
	}
	if (dateValue.length < 10)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	var restr = /[^0-9-]/;
	
	if (restr.test(dateValue))
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	var values = dateValue.split("-");
	if (values == null || values.length != 3)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	

	var month = values[1];
	var day = values[0];
	var year = values[2];
	
	if(month.length != 2)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	if(day.length != 2)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	if(year.length != 4)
	{
		alert("<i18n:message key='check_date'/>");
		return false;
	}
	
	if (month < 1 || month > 12)
	{
		alert("<i18n:message key='check_date_month'/>");
		return false;
	}
	
	if ((month == 1 || month == 3 || month == 5 || month == 7 || month == 8 || month == 10 || month == 12) && (day < 1 || day > 31))
	{
		alert("<i18n:message key='check_date_day1'/>");
		return false;
	}
	
	 
	 if(month == 2 && ((year % 4 == 0 && year % 100 != 0) || (year % 100 == 0 && year % 400 == 0)) && (day < 1 || day > 29))
	{
		alert("<i18n:message key='check_date_day2'/>");
		return false;
	}
	if(month == 2 && !((year % 4 == 0 && year % 100 != 0) || (year % 100 == 0 && year % 400 == 0)) && (day < 1 || day > 28))
	{
		alert("<i18n:message key='check_date_day3'/>");
		return false;
	}
	if ((month == 4 || month == 6 || month == 9 || month == 11)  && (day < 1 || day > 30))
	{
		alert("<i18n:message key='check_date_day4'/>");
		return false;
	}
	
	//judge if the date is right
	var testDate = new Date(year, month-1, day);
	var testYear = testDate.getFullYear();
	var testMonth = testDate.getMonth()+1;
	var testDay = testDate.getDate();
	//alert(testYear);
	//alert(testMonth);
	//alert(testDay);
	
	if (testYear==year && testMonth== month && testDay== day)
	{
		return true;
	}
	else
	{
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}	
	
}

//check the format of date
function checkSetCertDate(dateValue)
{
	if (dateValue.length < 10)
	{
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}
	var restr = /[^0-9-]/;
	if (restr.test(dateValue))
	{
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}
	var values = dateValue.split("-");
	if (values == null || values.length != 3)
	{
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}

	var month = values[1];
	var day = values[0];
	var year = values[2];
	
	if(month.length != 2)
	{
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}
	if(day.length != 2)
	{
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}
	if(year.length != 4)
	{
		alert("<i18n:message key='check_date_wrong'/>");
		return false;
	}
	
	if (month < 1 || month > 12)
	{
		alert("<i18n:message key='check_date_month'/>");
		return false;
	}
	
	if ((month == 1 || month == 3 || month == 5 || month == 7 || month == 8 || month == 10 || month == 12) && (day < 1 || day > 31))
	{
		alert("<i18n:message key='check_date_day1'/>");
		return false;
	}
	
	 
	 if(month == 2 && ((year % 4 == 0 && year % 100 != 0) || (year % 100 == 0 && year % 400 == 0)) && (day < 1 || day > 29))
	{
		alert("<i18n:message key='check_date_day2'/>");
		return false;
	}
	if(month == 2 && !((year % 4 == 0 && year % 100 != 0) || (year % 100 == 0 && year % 400 == 0)) && (day < 1 || day > 28))
	{
		alert("<i18n:message key='check_date_day3'/>");
		return false;
	}
	if ((month == 4 || month == 6 || month == 9 || month == 11)  && (day < 1 || day > 30))
	{
		alert("<i18n:message key='check_date_day4'/>");
		return false;
	}

	if (year < 2000 || year > 2098)
	{
		alert("<i18n:message key='check_year_bound_to2098'/>");
		return false;
	}		
	//judge if the date is right
	var testDate = new Date(year, month-1, day);
	var testYear = testDate.getFullYear();
	var testMonth = testDate.getMonth()+1;
	var testDay = testDate.getDate();
	//alert(testYear);
	//alert(testMonth);
	//alert(testDay);
	
	if (testYear==year && testMonth== month && testDay== day)
	{
		return true;
	}
	else
		{
			alert("<i18n:message key='check_date_wrong'/>");
			return false;
		}	
	
}

