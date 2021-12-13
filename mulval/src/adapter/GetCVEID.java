/*
Get CVE IDs from each OVAL report.
Author(s) : Su Zhang, Xinming Ou
Copyright (C) 2011, Argus Cybersecurity Lab, Kansas State University

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


import java.io.File;
import java.io.FileWriter;
import java.util.Iterator;
import java.util.List;

import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;

//import com.sun.org.apache.xalan.internal.xsltc.runtime.Hashtable;
import java.util.Hashtable;

public class GetCVEID {
	
	public static void main(String[] args) {
		
		String name = args[0];

		System.out.println("update seccusfully , file name : "+name);
		
		getCVEs(name);

	}
	public static String getHostname(String filename){
		
		String hname="";
		try{
			
			SAXReader saxReader = new SAXReader(); 
			
			Document document = saxReader.read(filename);
			// System.out.println("document file : "+document);
			// Element test = (Element) document.selectSingleNode(""); // test
			
			Element   hostname   =(Element)   document.selectSingleNode( "/*[local-name(.)='oval_results']/*[local-name(.)='results']/*[local-name(.)='system']/*[local-name(.)='oval_system_characteristics']/*[local-name(.)='system_info']/*[local-name(.)='primary_host_name']"   ); // original
			// Element hostname  = // testing 
			String hname1=hostname.getText(); // orginal
			// String hname1=""; // testing 


			
			// System.out.println("hname1 : "+hname1);
                 
			int in=hname1.indexOf('.');  //only keep the string before the first dot
		
			//if no dot, then ignore it
			if(in==-1)
			      hname=hname1 ;
		        //else take the machine domain name 
			else
			    hname=hname1.substring(0,in);
		  
			// System.out.println("host name is: "+hname);
		}

		catch (Exception e){
	 
			e.printStackTrace();
		}

		return hname;	// orginal 
		// return "127.0.0.1"; // testing 
		
	}

	@SuppressWarnings("unchecked")
	public static void getCVEs(String filename){
	
		Hashtable ovalIDs= makehashTable(filename);
		
		String hname=getHostname(filename);
		
		try{
			
			FileWriter fr= new FileWriter("CVE.txt");
		
			fr.write(hname+"\n");

			SAXReader saxReader = new SAXReader(); 
			
			Document document = saxReader.read(new File(filename));
			// System.out.println("document : "+document);

			Element   definitions   =(Element)   document.selectSingleNode( "/*[local-name(.)='oval_results']/*[local-name(.)='oval_definitions']/*[local-name(.)='definitions']"   ); // original 
			// Element   definitions   =(Element)   document.selectSingleNode( "/*[local-name(.)='oval_definitions']/*[local-name(.)='oval_definitions']/*[local-name(.)='definitions']"   ); // testing 
			// System.out.println("test definition if work !!");
			// System.out.println("definitions : "+definitions); // test



			List definition=document.selectNodes("/*[local-name(.)='oval_results']/*[local-name(.)='oval_definitions']/*[local-name(.)='definitions']/*[local-name(.)='definition']" ); 
			
			Iterator def = definition.iterator();

			while(def.hasNext()){

				Element deft = (Element)def.next();
				// System.out.println(deft);

				//skip if the element is inventory
				
				String type = deft.attributeValue("class");
				// System.out.println("test type if work !!");
				// System.out.println("Type : "+type);
				
				String id = deft.attributeValue("id");
				
				if(type.contains( "inventory"))
					
					continue;
				
				if(ovalIDs.containsKey(id)){
			          
					String cve = deft.element("metadata").element("reference").attributeValue("ref_id");
					// System.out.println("CVE : "+cve);
					
					fr.write(cve+"\n");
				
				}
			}

			fr.close();
			
		}
		 catch (Exception e){
			 System.out.println("Error : "+e);
			 e.printStackTrace();
		 }
		
	}

	@SuppressWarnings("unchecked")
	public static Hashtable<String, Boolean>  makehashTable(String filename){
		
		Hashtable<String, Boolean> hs= new Hashtable<String, Boolean>();
		
		try{
			SAXReader saxReader = new SAXReader(); 
		    
			Document document = saxReader.read(new File(filename));
		
			List <String>ldid = document.selectNodes("/*[local-name(.)='oval_results']/*[local-name(.)='results']/*[local-name(.)='system']/*[local-name(.)='definitions']/*[local-name(.)='definition']/@definition_id" ); 
		
			Iterator itdid = ldid.iterator();
		
			List <String>rst = document.selectNodes("/*[local-name(.)='oval_results']/*[local-name(.)='results']/*[local-name(.)='system']/*[local-name(.)='definitions']/*[local-name(.)='definition']/@result" ); 
		
			Iterator result = rst.iterator();

			while(itdid.hasNext()){
			
				Attribute defid = (Attribute)itdid.next();
			
				Attribute rs = (Attribute)result.next();
		
				if (rs.getText().contains("true")){
				
					hs.put(defid.getText(), true);
				
				}

			}

		//	System.out.println(hs.size());
		
}
		catch (Exception e){
			 
			 e.printStackTrace();

		}
		
		return hs;
		
	}
	
}