/*
 * JEB Copyright PNF Software, Inc.
 * 
 *     https://www.pnfsoftware.com
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.pnf.androsig.apply.andsig;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.DexHashcodeList;
import com.pnf.androsig.apply.model.StructureInfo;
import com.pnf.androsig.apply.util.MetadataGroupHandler;
import com.pnf.androsig.apply.util.ReportHandler;
import com.pnf.androsig.common.AndroSigCommon;
import com.pnf.androsig.common.SignatureHandler;
import com.pnfsoftware.jeb.core.AbstractEnginesPlugin;
import com.pnfsoftware.jeb.core.IEnginesContext;
import com.pnfsoftware.jeb.core.IOptionDefinition;
import com.pnfsoftware.jeb.core.IPluginInformation;
import com.pnfsoftware.jeb.core.IRuntimeProject;
import com.pnfsoftware.jeb.core.OptionDefinition;
import com.pnfsoftware.jeb.core.PluginInformation;
import com.pnfsoftware.jeb.core.RuntimeProjectUtil;
import com.pnfsoftware.jeb.core.Version;
import com.pnfsoftware.jeb.core.events.J;
import com.pnfsoftware.jeb.core.events.JebEvent;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * Sign and apply signatures to find Android library methods. This plugin was ported from JEB1.
 * Currently a partial port. Refer to AndroidSigGenPlugin for additional documentation and how-to
 * use.
 * <p>
 * This is the second part of a 2-part plugin. First part: AndroidSigGenPlugin.
 * <p>
 * ********************* Version 2 *********************
 * <p>
 * 
 * @author Ruoxiao Wang
 */

public class AndroidSigApplyPlugin extends AbstractEnginesPlugin {
    private final ILogger logger = GlobalLog.getLogger(AndroidSigApplyPlugin.class);

    @Override
    public IPluginInformation getPluginInformation() {
        return new PluginInformation("Android Code Recognition",
                "Apply code signatures to identify Android libraries", "PNF Software",
                AndroSigCommon.VERSION, Version.create(3, 1, 0));
    }

    @Override
    public List<? extends IOptionDefinition> getExecutionOptionDefinitions() {
        return Arrays
                .asList(new OptionDefinition(null,
                        "The method will be ignored if its instruction count is no greater than \"method size bar\"\nValue range: >= 0 (Default value: 6)"),
                        new OptionDefinition("methodSizeBar", "Method size bar"),
                        new OptionDefinition(
                                null,
                                "The class will be ignored if (total matched instructions / total instructions) is no greater than \"matched instructions percentage bar\"\nValue range: 0.0 - 1.0 (Default value: 0.5)"),
                        new OptionDefinition("matchedInstusPercentageBar", "Matched instructions percentage bar"));
    }

    /**
     * Dispose of resources used by this plugin. The engines context calls this method upon plugin
     * unloading.
     */
    @Override
    public void dispose() {
    }

    @Override
    public void load(IEnginesContext arg0) {
    }

    /**
     * Same as {@link #execute(IEnginesContext, Map)}.
     * 
     * @param context the context in which this plugin executes (never null)
     */
    @Override
    public void execute(IEnginesContext context) {
        execute(context, null);
    }

    /**
     * Execute the plugin code within a given engines context. Plugin writers should consider this
     * as the execution entry-point.
     * 
     * @param context the context in which this plugin executes (never null)
     * @param executionOptions optional execution options provided by the caller; the list of
     *            options that could be provided is specified by getExecutionOptionDefinitions()
     */
    @Override
    public void execute(IEnginesContext context, Map<String, String> executionOptions) {
        IRuntimeProject prj = context.getProject(0);
        if(prj == null) {
            return;
        }

        DatabaseReference ref = new DatabaseReference();
        StructureInfo struInfo = new StructureInfo(executionOptions, ref);

        File sigFolder;
        try {
            sigFolder = SignatureHandler.getSignaturesFolder(context);
        }
        catch(IOException ex) {
            throw new RuntimeException(ex);
        }

        // Load all hashcodes
        ref.loadAllHashCodes(sigFolder);

        List<IDexUnit> dexlist = RuntimeProjectUtil.findUnitsByType(prj, IDexUnit.class, false);
        for(IDexUnit dex: dexlist) {
            DexHashcodeList dexHashCodeList = new DexHashcodeList();
            dexHashCodeList.loadAPKHashcodes(dex);

            // Create MetadataGroup
            MetadataGroupHandler.createCodeGroupMethod(dex, struInfo.getStructureResult());
            MetadataGroupHandler.createCodeGroupClass(dex, struInfo.getStructureResult());

            // Apply signature
            struInfo.rebuildStructure(dex, dexHashCodeList);

            if(Thread.currentThread().isInterrupted()) {
                logger.info("Tread Interrupted!");
                return;
            }

            // Notify system
            dex.notifyListeners(new JebEvent(J.UnitChange));
            // Output result
            ReportHandler.generateRecord(dex, struInfo, ref);

            /************* For testing *************/
            //ReportHandler.serializeReport(dex, struInfo);
            //ReportHandler.deserializeReport(dex, struInfo);          
            //generatePaper(dex);

            break;
        }
        logger.info("*************** Completed! ***************");
        // Just a hint to help jeb free memory consumption
        struInfo = null;
        ref = null;
        System.gc();
    }

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
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}