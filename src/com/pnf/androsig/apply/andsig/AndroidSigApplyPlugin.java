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

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.pnf.androsig.apply.matcher.DatabaseMatcherParameters;
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
        return DatabaseMatcherParameters.getExecutionOptionDefinitions();
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
        long t0 = System.currentTimeMillis();
        IRuntimeProject prj = context.getProject(0);
        if(prj == null) {
            return;
        }

        File sigFolder;
        try {
            sigFolder = SignatureHandler.getSignaturesFolder(context);
        }
        catch(IOException ex) {
            throw new RuntimeException(ex);
        }

        DatabaseReference ref = new DatabaseReference();
        StructureInfo struInfo = new StructureInfo(executionOptions, ref);

        try {
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
            logger.info("Signature recognition took %fs", (System.currentTimeMillis() - t0) / 1000.0);
        }
        finally {
            // Just a hint to help jeb free memory consumption
            struInfo = null;
            ref.close();
            ref = null;
            System.gc();
        }
    }

}