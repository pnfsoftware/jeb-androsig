/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;

/**
 * @author Ruoxiao Wang
 *
 */
public class LegacyPaper {

    /**
     * This function is mainly for testing. How to use: (1) We have the original App. Through
     * AndroidStudio we get the apk and using proguard we get the obsfuscated version apk and also
     * the mapping.txt. (2) Put the mapping.txt file on the Desktop. (3) Using Jeb2 and Android Code
     * Signature Generator plugin to generate the signature of the original apk. (4) Open
     * obsfuscated apk throught Jeb2 and run Android Code Recognition plugin.
     * 
     * Through this function, we can get two texts: (1) unmatchedClasses.txt: Compare mapping.txt
     * with our classMapping.txt, filter all matched classes and list the rest of the mapping in
     * mapping.txt which the plugin is failed to match. (2) wrongMatchedClasses.txt: List all the
     * class mappings that the plugin matched wrong. (3) conclusion.txt: Conclusion like correctly
     * matched percentage, matched class number...
     * 
     * @param unit mandatory target unit
     */
    @SuppressWarnings("unused")
    private void generatePaper(IDexUnit unit) {
        Map<String, String> map = new HashMap<>();
        Set<String> set = new HashSet<>();
        String desktopPath = System.getProperty("user.home") + "/Desktop";
        File classMapping = new File(desktopPath + "/classMapping.txt");
        File mapping = new File(desktopPath + "/mapping.txt");
        File unmatchedClasses = new File(desktopPath + "/unmatchedClasses.txt");
        File conclusion = new File(desktopPath + "/conclusion.txt");
        File wrongMatchedClasses = new File(desktopPath + "/wrongMatchedClasses.txt");

        double totalClasses = 0;
        double matchedClasses = 0;
        double correctClasses = 0;

        try(BufferedReader classMappingReader = new BufferedReader(new FileReader(classMapping));
                BufferedReader mappingReader = new BufferedReader(new FileReader(mapping));
                BufferedWriter unmatchedClassesWriter = new BufferedWriter(new FileWriter(unmatchedClasses));
                BufferedWriter conclusionWriter = new BufferedWriter(new FileWriter(conclusion));
                BufferedWriter wrongMatchedClassesWriter = new BufferedWriter(new FileWriter(wrongMatchedClasses));) {
            // Store targrt file
            String curLine = new String();
            while((curLine = mappingReader.readLine()) != null) {
                if(!curLine.startsWith(" ")) {
                    totalClasses++;
                    String[] curLines = curLine.split(" -> ");
                    map.put(curLines[1], curLines[0]);
                }
            }

            // Browse own file to filter the map
            String curLine1 = new String();
            while((curLine1 = classMappingReader.readLine()) != null) {
                matchedClasses++;
                String[] curLines = curLine1.split(" -> ");
                if(map.containsKey(curLines[1])) {
                    String target = map.get(curLines[1]).substring(map.get(curLines[1]).lastIndexOf(".") + 1);
                    String own = curLines[0].substring(curLines[0].lastIndexOf(".") + 1);
                    if(target.equals(own)) {
                        correctClasses++;
                        map.remove(curLines[1]);
                    }
                    else {
                        set.add(curLine1);
                    }
                }
                else {
                    set.add(curLine1);
                }
            }
            for(Map.Entry<String, String> entry: map.entrySet()) {
                unmatchedClassesWriter.write(entry.getValue() + "\t" + entry.getKey() + "\n");
            }
            for(String e: set) {
                wrongMatchedClassesWriter.write(e + "\n");
            }
            conclusionWriter.write("The number of All Signatures: " + "\n");
            conclusionWriter.write("Total class number: " + totalClasses + "\n");
            conclusionWriter.write("Matched class number: " + matchedClasses + "\t" + "Percentage: "
                    + (matchedClasses / totalClasses) + "\n");
            conclusionWriter.write("Correctly matched class number: " + correctClasses + "\t" + "Percentage: "
                    + (correctClasses / totalClasses) + "\n");
            conclusionWriter.write("Correctly matched percentage: " + (correctClasses / matchedClasses) + "\n");

        }
        catch(IOException e) {
            e.printStackTrace();
        }
    }
}
