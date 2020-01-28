#!/usr/bin/env Rscript

library("optparse")

output_formats <- c("png", "pdf", "postscript")

option_list = list(
  make_option(c("-i", "--input"), type="character", default=NULL,
	      help="filename of the transition matrix", metavar="character"),
  make_option(c("-o", "--output"), type="character", default=".",
              help="output directory name [default= %default]", metavar="character"),
  make_option(c("-l", "--label"), type="character", default="model_name",
              help="model name", metavar="character"),
  make_option(c("-f", "--format"), type="character", default="png",
              help="output format {png|jpeg|pdf|ps}  [default= %default]", metavar="character")
);

opt_parser = OptionParser(option_list=option_list);
opt = parse_args(opt_parser);

if (is.null(opt$input)){
  print_help(opt_parser)
  stop("argument must be supplied (input file).n", call.=FALSE)
}

output_dir <- opt$output
# read in the transition matrix from attack graph output
#trans <- read.csv(file="003/current.csv",head=TRUE,sep=",")
#labelTitle <- "Current:"
#trans <- read.csv(file="003/sdn_iav.csv",head=TRUE,sep=",")
#labelTitle <- "SDN IaV:"
#trans <- read.csv(file="003/sdn_noiav.csv",head=TRUE,sep=",")
#labelTitle <- "SDN No IaV:"
trans <- read.csv(file=opt$input,head=TRUE,sep=",")
labelTitle <- opt$label

# make a column of 1's of length tmatrixlength-1 (for mult at eof)
# this is (I-Q)^-1 for fundamental matrix convert to row?
C = matrix(1, rep(nrow(trans)-1),ncol=1,byrow=TRUE);

# Markov chain simultation function
run = function()
{

  cat("> ++++++++++++++++++++<\n " , labelTitle, 
     "\n> ++++++++++++++++++++\n");
  #Initialize Variables
  sessions = 2000;
  #!!! 
  #AbsorbingStates = 10;
  #countStates <- c(1:10);
  AbsorbingStates = nrow(trans);
  countStates <- c(1:nrow(trans));
  
  # samplePaths <- matrix(c(1:50),ncol=10,byrow=TRUE);
  
  sessionLen = c(1:sessions);
  
  for(j in 1:length(countStates)){
    countStates[j] <- 0;
  }
  
  for(j in 1:length(countStates)){
    countStates[j] <- 0;
  }
  
  for(k in 1:sessions){
    
    sessionLen[k] <- 0;
  }
  
  #cat("> Initial countStates:", paste(countStates), "\n");     
  #cat("> Initial sessionLen:", paste(sessionLen), "\n\n\n");          
  
  
  
  for(i in 1:sessions){
    # The state that we're starting in
    state = 1;
    #cat("Starting state:", state, "\n");
    
    countStates[state]= countStates[state]+1;
    
    # while Loop until Absorbing State is reached.
    #!!!
    #while (state!=10)
    # count the # of transitions between source and sink
    # including failed attempts to transition
    while (state!=nrow(trans))
    {
      # cat("> Dist:", paste(round(c(trans[state,]), 2)), "\n");
      newState <- sample(1:ncol(trans), 1, prob=trans[state,]) # move to next state (or stay in current)
      countStates[newState]<-countStates[newState]+1; # increment # times we've been here
      sessionLen[i]<-sessionLen[i]+1; # count the # of state transitions made before absorbing
      
      #cat("*", state, "->", newState, "\n");
      state = newState;
    }
    # end while Loop        
    
  }
  #cat("> countStates:", paste(countStates), "\n");      
  #cat("> sessionLen:", paste(sessionLen), "\n"); 
  #cat("> UniquesessionLen:", paste(unique(sessionLen)), "\n"); 
  
  UniqueSessionsLen <- unique(sessionLen);
  countUniqueSessionsLen <- c(1:max(UniqueSessionsLen));
  
  for(l in 1:max(UniqueSessionsLen)){
    
    countUniqueSessionsLen[l] <- 0;
  }
  
  # cat("> Initial countUniqueSessionsLen:", paste(countUniqueSessionsLen), "\n"); 
  
  for (l in 1:sessions){
    countUniqueSessionsLen[sessionLen[l]] = countUniqueSessionsLen[sessionLen[l]] + 1; 
    
    
  }
  # cat("> Final countUniqueSessionsLen:", paste(countUniqueSessionsLen), "\n\n\n"); 
  
  numerator =0; denominator =0;
  for(l in 1:max(UniqueSessionsLen)){
    
    numerator = numerator + l*countUniqueSessionsLen[l];
    denominator = denominator + countUniqueSessionsLen[l];
  }
  ExpectedLength = numerator/denominator;
  cat("> Expected Path Length:", paste(ExpectedLength), "\n\n\n"); 
  
  #barplot(countStates, main="State Distribution", xlab = "State #", ylab="Count");
  #barplot(countUniqueSessionsLen, main= labelTitle + " State Distribution", xlab = "State #", ylab="Count");
  plot_sd <- function(device) {
  do.call(
    device,
    args = list(paste(output_dir, paste(paste(labelTitle, "StateDist", sep="_"), device, sep = "."), sep="/"))
  )
  barplot(countUniqueSessionsLen, main= bquote(paste(.(labelTitle) ~ " State Distribution")), xlab = "State #", ylab="Count");
  dev.off();
  }
  sapply(output_formats, plot_sd)
  
  # plot histogram of the unique session lengths
  #cat("> cus length: ", paste(length(countUniqueSessionsLen)))
  plot_slh <- function(device) {
  do.call(
    device,
    args = list(paste(output_dir, paste(paste(labelTitle, "SLenHist", sep="_"), device, sep = "."), sep="/"))
  )

  xrange <- 1:150
  yrange <- 1:150
  
  plot(NULL, NULL, type="n", 
       xlim=c(0, length(countUniqueSessionsLen)), ylim=c(0, 300) ,
       axes=FALSE, ann=FALSE)
  
axis(1, at=0:length(countUniqueSessionsLen), lab=c(0:length((countUniqueSessionsLen))))
axis(2, las=1, at=20*0:15)
box()
title(main=bquote(paste(.(labelTitle) ~ " Path Length Distribution")), font.main=4)
title(xlab="Path Length")
title(ylab="Count")

lines(countUniqueSessionsLen, type='h')
lines(countUniqueSessionsLen, type='b')
#lines(UniqueSessionsLen, type='S')
#lines(UniqueSessionsLen)
dev.off();
  }
  sapply(output_formats, plot_slh)

  
  #!!!
  #Q = trans[1:9,1:9]; (from fundamental matrix eq)
  Q = trans[1:nrow(trans)-1,1:nrow(trans)-1];
  cat("> Q[]:\n");
  print(Q);
  # Identity Matrix
  #!!
  #I = diag(9);
  I = diag(nrow(trans)-1);
  #print(I);
  # Calculate Inverse
  N = solve(I-Q); 
  #cat("> Npre round:", paste(N), "\n\n\n"); 
  round(N,2);
  cat(">  F[]`:\n");
  print(N);
  #C;
  # Matrix Multiplication
  b <- N %*% C;
  cat(rownames(b));
  #print(b)
  #cat('\n\n');
  
  cat('\n\nNRA:\n');
 # print(rownames(N))
  NRA <- N[1,]
  print(NRA)
  
  #bp<-barplot(b,  main=bquote(paste( .(labelTitle) ~ "  Expected Time at State(x)")), xlab = "State ID", ylab="Count", beside=TRUE, names.arg=rownames(b), space=.5, ylim=c(0,max(b)));

  #png(cat(labelTitle, "_ETS.png", sep = ""))
  #postscript(paste0(labelTitle, "_ETS.png"))
  plot_ets <- function(device) {
  do.call(
    device,
    args = list(paste(output_dir, paste(paste(labelTitle, "ETS", sep="_"), device, sep = "."), sep="/"))
  )
  bp<-barplot(NRA,  main=bquote(paste( .(labelTitle) ~ "  Expected Time at State(x)")), xlab = "State ID", ylab="Count", beside=TRUE, names.arg=rownames(b), space=.5, ylim=c(0,max(NRA)));
  text(bp, 0, round(NRA, 1),cex=1,pos=3)
  box()
  dev.off();
  }
  sapply(output_formats, plot_ets)
  cat("> trans:\n");
  print(trans);
  
  R = trans[1:nrow(trans)-1,nrow(trans)];
  cat("> R:\n");
  print(R);
  
  cat("> FR:\n");
  B <- N %*% R;
  print(B);
  
  
  cat('\n\nFC:\n');
  N %*% C
}

run()
